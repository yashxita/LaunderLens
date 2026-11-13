"""
gate.py  —  WITNESS: nonmalleable endorsement of delegated values.

The sink gate that ties S1–S6 and V together (design/DEFENSE_DESIGN.md §4).

For every tool call the agent proposes:

  read tool ............................................. ALLOW (never gated)
  S2  sink not declared by S1, or call budget used up ...... BLOCK  (BLOCKED-control)
  per security-relevant argument:
      value typed by the user ............................. ENDORSED-user
      free text ........................................... UNCHECKED (out of scope)
      reference / user-only ............................... membership check
      identity / quantity, by slot source:
        user     -> must be in the prompt
        trusted  -> must be a trusted value or witness
        delegated:
          S3  enumerate every typed candidate C in the declared source;
              proposal not in C ............................ BLOCK  (fail-closed)
          S4  drop candidates equal to the user's own values
              exactly one left ............................. ENDORSE (unique)       [V may escalate]
          S5  exactly one candidate has trusted evidence:
                it is the proposal ......................... ENDORSE (corroborated)
                it is another candidate .................... BLOCK  (conflict)
          S6  closed-choice confirmation ................... ENDORSE (confirmed) / BLOCK / ESCALATE

A call is allowed only if every argument is allowed. Any BLOCK blocks; otherwise
any ESCALATE escalates (refused in autonomous mode).

No LLM sits on the approve path. The only LLM uses are the optional S1 planner
(sees the prompt only) and the optional veto (can only downgrade).
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict, replace
from typing import Any, Callable, Optional

_DEFENSES = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DEFENSES not in sys.path:
    sys.path.insert(0, _DEFENSES)

from defense_base import Defense, DefenseContext, ActionDecision  # noqa: E402

from .confirm import ABSTAIN, ORACLE, ConfirmationPolicy
from .ledger import CounterpartyLedger
from .policy import (FREE_TEXT, IDENTITY, QUANTITY, REFERENCE, USER_ONLY, ArgSpec,
                     SuitePolicy, get_policy, infer_suite)
from .recognisers import Candidate, canonical, dedupe, find_candidates, map_proposal
from .slots import (DELEGATED, TRUSTED, USER, IntentPlan, SinkPlan, SlotSpec, ground_truth_plan,
                    heuristic_plan, llm_plan)
from .state import Observation, TrustedState, build_trusted_state
from .veto import LLMVeto

# ---------------------------------------------------------------------------
# Labels (one per argument; the call's label is its decisive argument's label)
# ---------------------------------------------------------------------------
READ = "READ"
UNCHECKED = "UNCHECKED-free-text"
ENDORSED_USER = "ENDORSED-user"
ENDORSED_TRUSTED = "ENDORSED-trusted"
ENDORSED_PRESENT = "ENDORSED-present"
ENDORSED_UNIQUE = "ENDORSED-unique"
ENDORSED_CORROBORATED = "ENDORSED-corroborated"
ENDORSED_CONFIRMED = "ENDORSED-confirmed"
ENDORSED_ANY = "ENDORSED-any-candidate"          # only reachable with uniqueness=False (ablation)
BLOCKED_CONTROL = "BLOCKED-control"
BLOCKED_UNSUPPORTED = "BLOCKED-unsupported"
BLOCKED_CONFLICT = "BLOCKED-conflict"
BLOCKED_USER = "BLOCKED-user-rejected"
ESCALATED = "ESCALATED"

ALLOW, ESCALATE, BLOCK = "allow", "escalate", "block"
_SEVERITY = {ALLOW: 0, ESCALATE: 1, BLOCK: 2}
# Among arguments with the same decision, report the one carrying the most
# security-relevant evidence (an identity endorsement over a name lookup).
_LABEL_RANK = {READ: 0, UNCHECKED: 1, ENDORSED_PRESENT: 2, ENDORSED_USER: 3, ENDORSED_TRUSTED: 4,
               ENDORSED_ANY: 5, ENDORSED_UNIQUE: 6, ENDORSED_CORROBORATED: 7, ENDORSED_CONFIRMED: 8}


@dataclass
class WitnessConfig:
    """Every switch is an ablation knob; the defaults are full WITNESS."""
    name: str = "witness"
    slots: str = "ground_truth"            # ground_truth | heuristic | llm
    confirm_mode: str = ABSTAIN            # abstain | oracle
    uniqueness: bool = True                # False: accept any candidate in C (AuthGraph/AuthorityFlow-like)
    delegation: bool = True                # False: never endorse delegated values (ROPE/CaMeL-like)
    elimination: bool = True               # S4
    corroboration: bool = True             # S5
    fail_closed: bool = True               # S3 membership requirement
    strict_quantities: bool = False        # amounts get the identity pipeline
    require_known_counterparty: bool = False  # a unique identity still needs trusted evidence
    veto: bool = False                     # optional LLM veto (needs llm)
    strict_checksum: bool = False          # ISO mod-97 for IBANs (off for AgentDojo)
    trusted_seed: Optional[dict] = None    # per-suite seed (state.load_seed)
    ledger_path: Optional[str] = None      # persist pins across runs (trust on first use)
    literal_sinks: bool = True             # undeclared sink allowed if every identity arg is user-typed


CONFIGS: dict[str, WitnessConfig] = {
    "witness": WitnessConfig(),
    "witness_assisted": WitnessConfig(name="witness_assisted", confirm_mode=ORACLE),
    "witness_veto": WitnessConfig(name="witness_veto", veto=True),
    "witness_known_counterparty": WitnessConfig(name="witness_known_counterparty",
                                                require_known_counterparty=True),
    "witness_strict_qty": WitnessConfig(name="witness_strict_qty", strict_quantities=True),
    # ablations that reproduce prior design points
    "ablate_uniqueness": WitnessConfig(name="ablate_uniqueness", uniqueness=False),     # ~AuthGraph/AuthorityFlow
    "ablate_delegation": WitnessConfig(name="ablate_delegation", delegation=False),     # ~ROPE/CaMeL
    "ablate_elimination": WitnessConfig(name="ablate_elimination", elimination=False),
    "ablate_corroboration": WitnessConfig(name="ablate_corroboration", corroboration=False),
    "ablate_failclosed": WitnessConfig(name="ablate_failclosed", fail_closed=False),
}


@dataclass
class ArgVerdict:
    arg: str
    value: Any
    label: str
    decision: str            # allow / escalate / block
    stage: str               # S1..S6, V, user, ...
    detail: dict = field(default_factory=dict)


class Witness(Defense):
    name = "witness"

    def __init__(self, llm: Optional[Callable[[str, str], str]] = None,
                 config: Optional[WitnessConfig] = None, suite: Optional[str] = None):
        self.llm = llm
        self.cfg = config or WitnessConfig()
        self.name = self.cfg.name
        self.suite = suite
        self.plan: Optional[IntentPlan] = None
        self._plan_ready = False                       # read by apply_defense_to_trace
        self.ledger = CounterpartyLedger(self.cfg.ledger_path)
        self.confirm = ConfirmationPolicy(mode=self.cfg.confirm_mode)
        self.veto = LLMVeto(llm) if (self.cfg.veto and llm is not None) else None
        self._calls_allowed: Counter = Counter()
        self.audit: list[dict] = []
        self.used_unordered_observations = False

    # ------------------------------------------------------------------ S1
    def use_ground_truth_slots(self, suite: str, task_id: str) -> bool:
        """Mirror of AuthGraph.use_ground_truth_plan; returns False if no plan exists."""
        self.suite = suite
        plan = ground_truth_plan(suite, task_id)
        if plan is None:
            return False
        self.plan = plan
        self._plan_ready = True
        return True

    def setup(self, user_prompt: str, tool_catalog: list[dict]) -> None:
        names = [t.get("name", "") for t in (tool_catalog or [])]
        self.suite = self.suite or infer_suite(names)
        if self.suite is None:
            return  # decided lazily on the first review(), once tool names are visible
        self._compile(user_prompt, names)

    def _compile(self, user_prompt: str, tool_names: list[str]):
        if self.cfg.slots == "llm" and self.llm is not None:
            self.plan = llm_plan(self.suite, user_prompt, self.llm, read_tools=tool_names)
        else:
            self.plan = heuristic_plan(self.suite, user_prompt)
        self._plan_ready = True

    def set_oracle(self, values: dict[tuple[str, str], list[str]]):
        """Values the simulated user would pick in S6 (ORACLE mode only)."""
        self.confirm.oracle_values = dict(values)

    # ------------------------------------------------------------------ review
    def review(self, context: DefenseContext) -> ActionDecision:
        action = context.current_action or {}
        tool = action.get("tool", "")
        args = action.get("args") or {}
        observations = self._observations(context)

        if self.suite is None:
            seen = [a.get("tool", "") for a in context.prior_actions] + [tool]
            seen += [t.get("name", "") for t in (context.tool_catalog or [])]
            self.suite = infer_suite(seen)
        if self.suite is None:
            return self._finish(tool, args, [ArgVerdict("*", None, BLOCKED_CONTROL, BLOCK, "S0",
                                                        {"why": "unknown suite; no policy"})])
        policy = get_policy(self.suite)

        if not policy.is_sink(tool):
            return self._finish(tool, args, [ArgVerdict("*", None, READ, ALLOW, "read")])

        if self.plan is None:
            self._compile(context.user_prompt, [a.get("tool", "") for a in context.prior_actions])

        state = build_trusted_state(policy, context.user_prompt, observations,
                                    seed=self.cfg.trusted_seed, ledger=self.ledger)

        # S2: control fence
        sink = self.plan.sinks.get(tool)
        if sink is None:
            sink = self._literal_sink(policy, tool, args, state)
        if sink is None:
            return self._finish(tool, args, [ArgVerdict("*", None, BLOCKED_CONTROL, BLOCK, "S2",
                                                        {"why": f"{tool} not declared by the intent plan"})])
        if self._calls_allowed[tool] >= sink.max_calls:
            return self._finish(tool, args, [ArgVerdict("*", None, BLOCKED_CONTROL, BLOCK, "S2",
                                                        {"why": f"call budget {sink.max_calls} for {tool} used"})])
        verdicts: list[ArgVerdict] = []
        for arg, value in args.items():
            spec = policy.arg_spec(tool, arg)
            if value is None or value == "" or (isinstance(value, (list, tuple)) and not value):
                continue
            items = list(value) if (spec.is_list and isinstance(value, (list, tuple))) else [value]
            for item in items:
                verdicts.append(self._eval_arg(tool, arg, item, spec, sink.slots.get(arg),
                                               policy, state, observations, context.user_prompt))
        if not verdicts:
            verdicts.append(ArgVerdict("*", None, UNCHECKED, ALLOW, "args", {"why": "no arguments"}))
        return self._finish(tool, args, verdicts)

    # ------------------------------------------------------------------ one argument
    def _eval_arg(self, tool: str, arg: str, value, spec: ArgSpec, slot: Optional[SlotSpec],
                  policy: SuitePolicy, state: TrustedState, observations: list[Observation],
                  prompt: str) -> ArgVerdict:
        cfg = self.cfg

        # Anything the user typed literally is authorised by the user.
        if spec.vtype and canonical(value, spec.vtype) in state.prompt_values.get(spec.vtype, set()):
            return ArgVerdict(arg, value, ENDORSED_USER, ALLOW, "user")

        if spec.role == FREE_TEXT:
            return ArgVerdict(arg, value, UNCHECKED, ALLOW, "free_text")

        if spec.role == USER_ONLY:
            ok = str(value) in (prompt or "")
            return ArgVerdict(arg, value, ENDORSED_USER if ok else BLOCKED_UNSUPPORTED,
                              ALLOW if ok else BLOCK, "user",
                              {} if ok else {"why": "user-only argument not in the prompt"})

        if spec.role == REFERENCE:
            needle = str(value).strip().casefold()
            pool = [prompt or ""] + [o.text for o in observations]
            ok = bool(needle) and any(needle in (t or "").casefold() for t in pool)
            return ArgVerdict(arg, value, ENDORSED_PRESENT if ok else BLOCKED_UNSUPPORTED,
                              ALLOW if ok else BLOCK, "reference",
                              {} if ok else {"why": "reference not seen in prompt or any observation"})

        # identity / quantity from here on
        vtype = spec.vtype
        if slot is None:
            return ArgVerdict(arg, value, BLOCKED_CONTROL, BLOCK, "S2",
                              {"why": f"argument {arg} has no slot in the intent plan"})

        # Quantities are membership-checked against everything the agent was allowed
        # to read; the planner's choice of source is ignored here. A weak planner
        # labelling the bill's amount "trusted" (24/29 banking traces with qwen 14B)
        # must not cost the payment, and an amount cannot redirect who is paid.
        if spec.role == QUANTITY and not cfg.strict_quantities:
            return self._quantity(arg, value, vtype, policy, state, observations)

        if slot.source == USER:
            return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S1",
                              {"why": "slot is user-sourced but the value is not in the prompt"})

        if slot.source == TRUSTED:
            v = canonical(value, vtype)
            prov = state.witness_of(vtype, v) or ("self" if state.is_self(vtype, v) else None)
            if prov:
                return ArgVerdict(arg, value, ENDORSED_TRUSTED, ALLOW, "S5", {"provenance": prov})
            return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S5",
                              {"why": "slot is trusted-sourced but no trusted record holds this value"})

        # ---------------- DELEGATED ----------------
        if not cfg.delegation:
            return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S1",
                              {"why": "delegated values disabled (ablate_delegation)"})

        docs = self._delegated_docs(slot, policy, observations)
        if not docs:
            return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S3",
                              {"why": f"delegated source {list(slot.source_tools) or 'any'} not read yet"})

        # S3: typed enumeration
        C = dedupe(c for d in docs for c in find_candidates(d.text, vtype, d.tool, d.index,
                                                            strict_checksum=cfg.strict_checksum))
        hits = map_proposal(value, vtype, C)
        detail = {"candidates": [c.raw for c in C], "sources": sorted({d.tool for d in docs})}
        if not hits:
            if cfg.fail_closed:
                return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S3",
                                  {**detail, "why": "proposed value is not a candidate in the delegated source"})
            own = Candidate(canonical(value, vtype), str(value), vtype, "agent", -1)
            C, hits = C + [own], [own]

        if not cfg.uniqueness:
            return ArgVerdict(arg, value, ENDORSED_ANY, ALLOW, "S3", detail)

        chosen = hits[0] if len(hits) == 1 else None
        if chosen is None:
            detail["why_ambiguous"] = "proposal maps to several candidates"

        # S4: trusted elimination (never removes the proposal itself)
        pool = C
        if cfg.elimination:
            pool = [c for c in C if not state.is_self(vtype, c.value) or c is chosen]
            removed = [c.raw for c in C if c not in pool]
            if removed:
                detail["eliminated_self"] = removed
        detail["pool"] = [c.raw for c in pool]

        if chosen is not None and len(pool) == 1:
            needs_witness = (cfg.require_known_counterparty and spec.role == IDENTITY
                             and not state.witness_of(vtype, chosen.value))
            if not needs_witness:
                vetoed, why = self._veto(chosen, arg, observations)
                if not vetoed:
                    return ArgVerdict(arg, value, ENDORSED_UNIQUE, ALLOW, "S4", detail)
                detail["veto"] = why
            else:
                detail["why_escalate"] = "unique but never-seen counterparty"
            return self._confirm(tool, arg, value, vtype, pool, chosen, observations, detail)

        # S5: trusted corroboration
        if cfg.corroboration:
            corr = [c for c in pool if state.witness_of(vtype, c.value)]
            detail["corroborated"] = {c.raw: state.witness_of(vtype, c.value) for c in corr}
            if len(corr) == 1:
                if chosen is not None and corr[0].value == chosen.value:
                    return ArgVerdict(arg, value, ENDORSED_CORROBORATED, ALLOW, "S5", detail)
                return ArgVerdict(arg, value, BLOCKED_CONFLICT, BLOCK, "S5",
                                  {**detail, "why": f"trusted evidence supports {corr[0].raw}, not this value",
                                   "corrected_value": corr[0].raw})

        # S6: closed-choice confirmation
        return self._confirm(tool, arg, value, vtype, pool, chosen, observations, detail)

    # ------------------------------------------------------------------ helpers
    def _quantity(self, arg, value, vtype, policy: SuitePolicy, state: TrustedState,
                  observations: list[Observation]) -> ArgVerdict:
        v = canonical(value, vtype)
        if state.witness_of(vtype, v):
            return ArgVerdict(arg, value, ENDORSED_TRUSTED, ALLOW, "S5")
        docs = observations if self.cfg.delegation else \
            [o for o in observations if o.tool in policy.trusted_tools]
        C = dedupe(c for d in docs for c in find_candidates(d.text, vtype, d.tool, d.index))
        if map_proposal(value, vtype, C):
            return ArgVerdict(arg, value, ENDORSED_PRESENT, ALLOW, "S3",
                              {"sources": sorted({d.tool for d in docs})})
        return ArgVerdict(arg, value, BLOCKED_UNSUPPORTED, BLOCK, "S3",
                          {"why": "amount does not appear in anything the agent read",
                           "candidates": [c.raw for c in C]})

    def _literal_sink(self, policy: SuitePolicy, tool: str, args: dict,
                      state: TrustedState) -> Optional[SinkPlan]:
        """
        A sink the planner did not declare is still authorised when EVERY identity
        argument is a value the user typed (e.g. "her website: www.dora-website.com"
        -> get_webpage(url=that)). The user named the destination, so no document can
        have steered it. Fixes the LLM planner dropping Slack get_webpage. Budget 1.
        """
        if not self.cfg.literal_sinks:
            return None
        ident = [(a, s) for a, s in policy.sinks.get(tool, {}).items() if s.role == IDENTITY]
        if not ident:
            return None
        for arg, spec in ident:
            value = args.get(arg)
            items = value if isinstance(value, (list, tuple)) else [value]
            items = [i for i in items if i not in (None, "")]
            if not items or any(canonical(i, spec.vtype) not in state.prompt_values.get(spec.vtype, set())
                                for i in items):
                return None
        sp = SinkPlan(tool, 1, {a: SlotSpec(a, USER) for a, _ in ident})
        for a, s in policy.sinks.get(tool, {}).items():
            if s.role == QUANTITY:
                sp.slots[a] = SlotSpec(a, DELEGATED, ())
        self.plan.sinks[tool] = sp       # later calls share the same budget
        return sp

    def _confirm(self, tool, arg, value, vtype, pool, chosen, observations, detail) -> ArgVerdict:
        texts = {o.index: o.text for o in observations}
        idx = self.confirm.ask(tool, arg, vtype, pool, texts)
        detail["question"] = self.confirm.transcript[-1]
        if idx is None:
            if self.confirm.mode == ORACLE:
                return ArgVerdict(arg, value, BLOCKED_USER, BLOCK, "S6",
                                  {**detail, "why": "user recognised none of the candidates"})
            return ArgVerdict(arg, value, ESCALATED, ESCALATE, "S6",
                              {**detail, "why": "conflict needs the user; autonomous mode abstains"})
        picked = pool[idx]
        if chosen is not None and picked.value == chosen.value:
            self.ledger.pin(vtype, picked.value, principal=f"{tool}.{arg}")
            return ArgVerdict(arg, value, ENDORSED_CONFIRMED, ALLOW, "S6", detail)
        return ArgVerdict(arg, value, BLOCKED_USER, BLOCK, "S6",
                          {**detail, "why": "user picked a different value", "corrected_value": picked.raw})

    def _veto(self, chosen: Candidate, arg: str, observations: list[Observation]) -> tuple[bool, str]:
        if self.veto is None:
            return False, ""
        doc = next((o.text for o in observations if o.index == chosen.obs_index), "")
        return self.veto.check(doc, chosen.raw, arg)

    @staticmethod
    def _delegated_docs(slot: SlotSpec, policy: SuitePolicy, observations: list[Observation]):
        if slot.source_tools:
            return [o for o in observations if o.tool in slot.source_tools]
        # "any untrusted read": everything except high-integrity tools and parsed records
        return [o for o in observations
                if o.tool not in policy.trusted_tools and o.tool not in policy.record_tools]

    def _observations(self, context: DefenseContext) -> list[Observation]:
        log = getattr(context, "observation_log", None)
        if log:
            return [Observation(int(o.get("index", i)), o.get("tool", ""), o.get("args") or {},
                                o.get("text") or "") for i, o in enumerate(log)]
        # Fallback for callers that only pass the tool->text map. That map can
        # include observations made AFTER the current call, so flag it.
        if context.observations:
            self.used_unordered_observations = True
        return [Observation(i, t, {}, txt or "") for i, (t, txt) in enumerate((context.observations or {}).items())]

    def _finish(self, tool: str, args: dict, verdicts: list[ArgVerdict]) -> ActionDecision:
        decisive = max(verdicts, key=lambda v: (_SEVERITY[v.decision], _LABEL_RANK.get(v.label, 9)))
        allow = decisive.decision == ALLOW
        if allow and self.suite and tool in get_policy(self.suite).sinks:
            self._calls_allowed[tool] += 1
        why = decisive.detail.get("why", "")
        reason = f"{decisive.label} [{decisive.stage}] {decisive.arg}" + (f": {why}" if why else "")
        self.audit.append({
            "tool": tool, "args": args, "allow": allow, "decision": decisive.decision,
            "label": decisive.label, "stage": decisive.stage,
            "args_verdicts": [asdict(v) for v in verdicts],
        })
        return ActionDecision(
            allow=allow,
            trust_label=None if decisive.label == READ else ("trusted" if allow else "untrusted"),
            screener_decision=decisive.label,
            reason=reason,
            layer=decisive.stage,
        )


def make_witness(config_name: str = "witness", llm=None, suite: Optional[str] = None,
                 **overrides) -> Witness:
    """Build a Witness from a named config in CONFIGS, with optional field overrides."""
    if config_name not in CONFIGS:
        raise KeyError(f"unknown WITNESS config {config_name!r}; known: {sorted(CONFIGS)}")
    cfg = replace(CONFIGS[config_name], **overrides) if overrides else replace(CONFIGS[config_name])
    return Witness(llm=llm, config=cfg, suite=suite)
