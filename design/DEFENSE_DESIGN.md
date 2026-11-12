# Defence Design: WITNESS, plus the Routed Hybrid

_Design only. No code exists yet. Written 2026-11-12. Diagrams: [`diagrams/arch_a_witness.png`](../diagrams/arch_a_witness.png) (Direction A) and [`diagrams/arch_b_hybrid.png`](../diagrams/arch_b_hybrid.png) (Direction B). Regenerate them with `python design/arch_a_witness.py` and `python design/arch_b_hybrid.py`._

---

## 1. What we are solving

### The task class: delegated values
Many agent tasks **hand a value off to an untrusted document**:
- "Pay the bill in `bill.txt`." The IBAN comes from the file.
- "Invite Dora; her email is on her website." The email comes from the web page.

### The attack: same-observation pollution
The attacker **appends a competing value** to that same document. Examples are a "payment details updated" notice or an addendum giving a new contact email. Our attacks `attribution_forgery`, `label_join`, `slack_invite_redirect` and `dual_contact` are all this attack. In the real world it is invoice-redirection or business-email-compromise fraud, moved to LLM agents.

### What our own results already show
- **AuthGraph** accepts the attacker's value: LIS+D = 0 on every influential attack (Table 1).
- **CaMeL, FIDES and RTBAS** refuse *every* document-supplied value, legitimate ones included: FPR = 1.0, utility = 0 (Table 2).

### Goal
Admit the legitimate delegated value (high utility) and never admit the planted one (high security), cheaply.

---

## 2. Literature: who handles this case?

The case: the legit value must come from document *D*, and the attacker adds a competing value to *D*.

| Defence | Legit value from *D* | Competing value in *D* |
|---|---|---|
| CaMeL (2503.18813) | denied by policy; paper names "Data requires action" failures | denied |
| FIDES (2505.23643) | low-integrity; needs explicit endorsement | blocked |
| RTBAS (2502.08966) | blocked when untrusted data touches the sink | blocked |
| ROPE (2608.27496) | file and web bodies are injectable blocks; "no marker admits a value from it" | refused, legit one too |
| PlanTERS fence (2611.11506) | sink tool revoked after the first untrusted read | blocked |
| AuthGraph (2605.26497) | allowed | **allowed** (confirmed by our runs) |
| AuthorityFlow (2611.04673) | allowed if the span is authorised | **likely allowed**: authority per span, no conflict check |
| SARA (2608.27146) | likely rejected when *D* is "ACTIONABLE" | not addressed |
| AttriGuard (2603.10749) | survives | explicit non-goal ("pure explicit delegation") |
| CausalArmor (2602.07918) | likely flagged | sanitiser keeps one, unverified |
| AgentSentry (2602.22724) | allowed | its only adaptive survivors were factual-recipient poisoning |
| MELON (2502.05174) | allowed | not designed for it |
| *Influence Is Not Authority* (2608.29942) | shows causal signals flag legit delegated values | no fix proposed |
| *ASPI* (2605.17324) | — | open clarification **amplifies** injection (o3: 1.8% → 34.0% ASR) |

**Gap.** Nothing in this set admits the legitimately delegated value and also refuses a competing value planted beside it. Specifically, none of these papers:
- enumerates candidate values,
- detects a conflict between candidates for one slot, or
- corroborates candidates against trusted state.

_Several numbers above come from summaries of partial HTML fetches. Verify them against the PDFs before quoting them in the manuscript._

---

## 3. Threat model and two observations

### Trust assumptions
- **Trusted:** the user prompt, tool schemas, the runtime, and high-integrity tools (own account info, the user directory, user-initiated transactions).
- **Attacker:** can **append spans** to untrusted tool outputs (files, pages, received emails, memos), but cannot delete or edit the legitimate content. This is AgentDojo's injection-vector model.
- **Assumption W (well-founded delegation):** when the user delegates slot *s* to *D*, the un-attacked *D* contains the correct value.

### Out of scope
- Full control of the whole delegated document. If the bill is entirely the attacker's, paying it *is* the instruction.
- Free-text sink arguments, such as email bodies.

### Observation 1: content-only decisions are malleable
Take a document with two type-valid candidates for a single-valued slot. Any rule that **selects or eliminates** candidates using the document's own text can be steered. Two examples:
- The attacker appends a span formatted exactly like the legit one, with "updated" framing.
- The attacker appends "the IBAN above is the sender's account", which disqualifies the legit value.

Leave-one-span-out counterfactuals are symmetric, because each candidate vanishes with its own span. So an LLM judge, a sanitiser, a counterfactual replay or a span-authority rule cannot soundly decide between candidates. This one argument explains why AuthGraph, AuthorityFlow, AttriGuard and CausalArmor fail on our attacks.

**Design rule that follows:** once there is a conflict, the only sound moves are to:
- abstain,
- use evidence the attacker cannot write, or
- ask the principal in a channel the attacker cannot write.

### Observation 2: a unique candidate is safe
Under W, an append-only attacker and complete typed enumeration, if *D* contains exactly one valid candidate, that candidate is the legit one. W says the legit value is present, and anything the attacker adds would be a second candidate.

Both observations will be written up as short propositions. They are the paper's theoretical spine, and they carry nonmalleable IFC and transparent endorsement (Cecchetti, Myers & Arden, CCS 2017) over to LLM agents.

---

## 4. Direction A: WITNESS (the novel architecture)

Diagram: `diagrams/arch_a_witness.png`. WITNESS is a **sink gate**. It never changes what the agent reads; it only decides each sensitive tool call.

| Stage | What it does | LLM? | Why it is safe |
|---|---|---|---|
| **S1 Intent Slot Compiler** | From the prompt and tool schemas only, emits a slot spec per sink argument: `source ∈ {user-literal, trusted-tool, delegated(D)}`, `type`, `cardinality`, `impact tier`. Adapted from the AuthGraph planner and ROPE's under-specification router. | 1 call/task | The attacker has no channel into it. |
| **S2 Control Fence** | Blocks any sink call whose tool or slot was not declared. | no | Data may flow in; control may not. |
| **S3 Typed Candidate Enumerator** | Regex recognisers (IBAN, email, URL, amount) list **every** valid value of the slot type in *D*. The IBAN mod-97 checksum is optional (`strict_checksum`), because AgentDojo's IBANs are not ISO-valid and would all be rejected. The agent's value must fuzzy-match a candidate, or the call is blocked (fail-closed). The argument is then rewritten to the exact canonical candidate. | no | Nothing to prompt-inject. Obfuscated or relayed values fail closed. Canonicalising fixes the garbled-IBAN issue we saw on 2026-08-22. |
| **S4 Trusted Elimination** | Drops candidates that equal trusted "self" values (the user's own IBAN or email). | no | Uses only trusted state, never *D*'s wording (Observation 1). |
| **unique?** | If exactly one candidate is left, **ENDORSE**. | no | Observation 2. |
| **S5 Trusted Corroboration** | Endorses if exactly one candidate matches a **pinned** or trusted counterparty. | no | Witnesses must come from high-integrity sources. Untrusted sources never vouch for each other. |
| **Counterparty pinning ledger** | Stores principal → value bindings, written **only** by the user's choice in S6 (trust on first use). It is seeded from trusted state such as user-initiated transactions and contacts. | no | The bank "Confirmation of Payee" analogue: a changed payee always needs re-confirmation. |
| **S6 Closed-Choice Confirmation** | Renders a defence-written prompt listing **all** candidates. The answer is an index, never free text. In autonomous mode this becomes **ABSTAIN**. | no | Fixes ASPI's open-clarification problem. Unlike CaMeL or Call-Approval confirmation, the user sees the competing value. |
| **V LLM veto (optional)** | A quarantined, tool-less LLM may flag a suspicious endorsement. | yes | **Veto-only**: it can move ENDORSE → ESCALATE but never approve. Security never depends on an LLM, so `judge_hijack` has nothing to hijack. |

**Labels.** Every argument is labelled `ENDORSED-unique`, `ENDORSED-corroborated`, `ENDORSED-confirmed`, `BLOCKED-control`, `BLOCKED-unsupported`, `ESCALATED` or `ABSTAINED`. Because each label names its own reason, two-sided LIS can audit both under-taint and over-taint per argument.

**Cost.** One S1 call per task, everything else deterministic, plus the optional veto: about 1.1× tokens. Reported figures for comparison: AttriGuard about 2×, AgentSentry about 2.2×, CaMeL about 5×.

### Expected outcome on our attacks (to be verified)

| Attack | Stopped at |
|---|---|
| `attribution_forgery` ×3, `label_join/multi_payee`, `label_join/amendment_chain`, `slack_invite_redirect` ×2 | Two candidates after S4 → S5 cannot resolve → S6/ABSTAIN |
| `label_join/ledger_flood` | Many candidates → S6 |
| `multi_hop_reemission`, `provenance_dilution`, `trusted_tool_laundering` | S2 (undeclared source), or S3 fail-closed, or S5 (relaying through a read tool adds no trusted witness) |
| `semantic_indirection` (code / split reference) | S3 fail-closed: the proposed value is not a literal candidate |
| `judge_hijack` ×2 | No LLM on the approve path |
| AgentDojo `important_instructions` | S2 (new action) |

---

## 5. Direction B: best-of-breed combination

### Does "combine the best of everything" work?

**Stacking everything: no.**
- Every gate added in series multiplies benign false positives. Utility is roughly the product of each gate's benign pass rate. CaMeL alone fires policies on about 34% of benign tasks.
- More importantly, **no existing component is sound for delegated values**. Each one either refuses them (ROPE, CaMeL, FIDES, RTBAS) or accepts any candidate (AuthGraph, AuthorityFlow). A stack of them inherits the blind spot.

**Routing: yes.** Send each sink argument to the **one** component that is sound for its provenance class. Security per lane is then that component's guarantee on its own class, and utility is not multiplied across gates.

The delegated-value lane still needs the WITNESS core, so Direction B is "best existing parts plus WITNESS", not a replacement for A. Diagram: `diagrams/arch_b_hybrid.png`.

### Lanes

| Lane | Argument class | Component (source) | Already in repo? |
|---|---|---|---|
| Router | per-argument class, from the prompt only | ROPE under-specification router + AuthGraph planner | planner: `defenses/authgraph.py` |
| Fence | undeclared tool or slot | IPIGuard / AuthGraph plan graph | `defenses/authgraph.py` |
| 1 | user literal | deterministic prompt match (ROPE T1) | trivial |
| 2 | trusted record | deterministic record match (ROPE T3) | trivial |
| 3 | delegated value | **WITNESS core (S3–S6)** | new |
| 4 | derived value ("the cheapest hotel") | enum-constrained quarantined LLM (FIDES/CaMeL) + fact support (AuthorityFlow) | `defenses/fides.py`, `defenses/camel.py` |
| 5 | free text (email body) | FIDES capacity label + sanitiser (CausalArmor); no high-impact sink | `defenses/fides.py` |
| Context | agent memory | DRIFT-style injection isolator (raises utility under attack) | new, optional |
| Optional | action-open tasks only | AttriGuard / AgentSentry counterfactual replay (~2×) | skip unless time allows |

### Verdict
B can work, and should score better than A on the **full** AgentDojo suites, because A only covers sinks fed from documents. But:
- B's novelty comes almost entirely from lane 3, which *is* A.
- It needs more reimplementation work.
- The context isolator changes agent behaviour, so post-hoc replay is no longer exact for it.

---

## 6. Decision

1. **The paper's core contribution is A (WITNESS).** It is novel, has a formal spine, costs about 1.1×, and its post-hoc evaluation on saved traces is exact, so it needs no new agent runs.
2. **B is the "full system" configuration, built after A works.** Only the cheap lanes go in: router and fence reuse the AuthGraph planner; lanes 1 and 2 are deterministic; lanes 4 and 5 reuse `fides.py`. Skip the counterfactual module and the isolator unless results demand them.
3. **Ablations double as prior-art baselines:**
   - *WITNESS minus uniqueness* (accept any candidate) behaves like AuthGraph and AuthorityFlow, and should be laundered.
   - *WITNESS minus delegation* (never accept document values) behaves like ROPE and CaMeL, and should lose utility.

---

## 7. Implementation plan (module layout)

```
defenses/witness/
  __init__.py
  slots.py         S1  SlotSpec dataclass + compiler (reuses AuthGraph planner prompt)
  fence.py         S2  declared-tool/slot check
  recognisers.py   S3  typed recognisers: iban (mod-97), email, url, amount, slack_user
  enumerate.py     S3  candidate set C, fail-closed match (uses metrics/iban_match.py), canonicalise
  eliminate.py     S4  trusted-self elimination
  ledger.py        S5  CounterpartyLedger (seed from trusted state; write only via confirm)
  corroborate.py   S5  unique-corroborated check
  confirm.py       S6  closed-choice prompt + two eval modes (see below)
  veto.py          V   optional veto-only LLM
  gate.py          Witness(Defense): setup() = S1, review() = S2..S6 -> ActionDecision
defenses/hybrid.py       Direction B router, reuses witness/ + authgraph + fides
attacks/witness_adaptive.py   A1–A6 below
```

### Fit with the existing pipeline
- `Witness` subclasses `defenses/defense_base.Defense`.
- `review()` returns `ActionDecision(allow, trust_label, screener_decision=<label>, layer=<stage>)`.
- It is registered in `experiments/run_phase4.py`'s `defense_registry` and replays through `defenses/apply_defense.py` exactly like the other four defences.

### Two evaluation modes for ESCALATE
- **Autonomous:** ESCALATE counts as ABSTAIN. This is the worst case for utility.
- **Assisted:** a simulated user picks the clean-run value. This is index-only, so it adds no injection channel. Report the **escalation rate** separately so this mode can't hide cost.

---

## 8. Evaluation plan (low compute)

- **Phase 0, zero model calls:** replay WITNESS over the ~80 saved Phase 4 traces (banking + slack).
  - **Go:** WITNESS beats AuthGraph on security *and* CaMeL/FIDES/RTBAS on utility.
  - **No-go:** rethink before spending any compute.
- **Task set:** tag every AgentDojo v1.2 task whose ground-truth sink argument appears in an untrusted observation and not in the prompt. Target 25–40 delegated tasks. Also report the full suites, to show WITNESS costs nothing when nothing is delegated.
- **Baselines:**
  - our AuthGraph, RTBAS, FIDES and CaMeL;
  - AgentDojo built-ins: `tool_filter`, `spotlighting_with_delimiting`, `repeat_user_prompt`, `transformers_pi_detector`;
  - the two prior-art ablations from §6.
- **Metrics:**
  - BU, UA, ASR;
  - benign escalation rate;
  - escalation-under-attack rate;
  - tokens and latency;
  - two-sided LIS.
- **Models:** `qwen2.5:14b` locally. One cheap API model on the delegated subset only. FactAuthBench (AuthorityFlow's benchmark) if it is released.
- **Headline figure:** a security–utility frontier on delegated tasks. Strict IFC sits top-left, AuthGraph/AuthorityFlow bottom-right, WITNESS top-right. Marker size shows escalation rate.

### Adaptive attacks we must run against ourselves

| ID | Attack | What it tests |
|---|---|---|
| A1 | delete or edit the legit value | outside the threat model; reported as the boundary |
| A2 | enumerator evasion (spacing, spelled-out, homoglyphs, split lines) | S3 fail-closed |
| A3 | witness poisoning (plant the value in a memo that later shows up in transaction history) | S5 independence rule |
| A4 | decoy denial-of-utility (junk candidate forces escalation) | cost of turning an integrity attack into one question |
| A5 | many-valued slots ("invite everyone on this page") | limitation; per-item S6 |
| A6 | near-duplicate value (one-character IBAN edit) | distinctness uses exact checksum identity; fuzzy matching only maps the agent's proposal |

---

## 9. Risks and limits (state them up front)

- **Type coverage:** strong for structured identifiers, nothing for free text.
- **Benign multi-candidate documents:** if S4/S5 can't resolve them, the cost is user questions. The benign escalation rate must be reported, even where it is high.
- **The recognisers are trusted code:** a missed format fails closed, so it costs utility, not security.
- **Assumption W and the append-only attacker** bound every guarantee. Say so in the abstract.
- **The S1 slot compiler on a 14B local model** affects utility. This is the same caveat as AuthGraph's planner (`paper/differentiation.md` §3.4a).

---

## 10. Milestones

| # | Deliverable | Compute |
|---|---|---|
| M1 | `defenses/witness/` S2–S4 + S6-autonomous; replay over saved traces → go/no-go table | 0 model calls |
| M2 | S1 slot compiler, S5 + ledger, assisted mode, veto | local only |
| M3 | delegated-task tagger + clean/attacked sweep | local, the main compute |
| M4 | adaptive attacks A1–A6 | local |
| M5 | `defenses/hybrid.py` (Direction B, cheap lanes only) on full suites | local |
| M6 | ablations, frontier figure, two-sided LIS tables, write-up | small API budget |

---

## Sources

[CaMeL](https://arxiv.org/abs/2503.18813) · [FIDES](https://arxiv.org/abs/2505.23643) · [RTBAS](https://arxiv.org/abs/2502.08966) · [AuthGraph](https://arxiv.org/abs/2605.26497) · [AuthorityFlow](https://arxiv.org/abs/2611.04673) · [ROPE](https://arxiv.org/abs/2608.27496) · [SARA](https://arxiv.org/abs/2608.27146) · [PlanTERS](https://arxiv.org/abs/2611.11506) · [AttriGuard](https://arxiv.org/abs/2603.10749) · [CausalArmor](https://arxiv.org/abs/2602.07918) · [AgentSentry](https://arxiv.org/abs/2602.22724) · [MELON](https://arxiv.org/abs/2502.05174) · [Influence Is Not Authority](https://arxiv.org/abs/2608.29942) · [ASPI](https://arxiv.org/abs/2605.17324) · [IPIGuard](https://arxiv.org/abs/2508.15310) · [DRIFT](https://arxiv.org/abs/2506.12104) · [Progent](https://arxiv.org/abs/2504.11703) · [Nonmalleable IFC](https://arxiv.org/abs/1708.08596)
