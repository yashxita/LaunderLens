# Implementation Plan — Provenance Laundering / Label Integrity

**Project:** Measuring Label Integrity in Taint-Tracking Defences for Multi-Agent LLM Systems
**Type:** Attack + measurement paper (not a new defence)
**Benchmark:** AgentDojo (`github.com/ethz-spylab/agentdojo`)
**Primary targets:** RTBAS, AuthGraph · **Baselines:** FIDES, CaMeL

This is the build roadmap. Work top to bottom. Nothing after Phase 0 starts until the Phase-0 gates pass.

---

## 0. What we are actually building (scope recap)

Four deliverables, in priority order:

1. **LIS — Label Integrity Score.** A new metric that checks whether a defence's *own trust labels stayed honest*, not just whether the final action was blocked. This is our headline contribution.
2. **Four laundering attacks.** Concrete attacks that route a payload through a defence's screening/declassification step so it comes out mislabelled: *multi-hop re-emission, attention-screener bypass, attribution forgery, label-join granularity*.
3. **A literal-value baseline.** A dumb, deterministic detector (no model) that defines the *residual attack class* — the attacks that still need model-based detection.
4. **A reduction argument.** "Laundering-resistance is at least as hard as making the screener robust to adversarial text" — a bounded, honest claim, backed by one measured assumption.

Metrics we report everywhere: **ASR** (attack success rate), **LIS** (label integrity), **SER** (screener evasion rate), plus the **residual class**.

### 0.1 Deliberately out of scope (decisions, not omissions)

These were considered earlier and consciously cut. Recorded here so reviewers/advisors see them as choices:

- **No new defence / "certified fix."** This is an attack-and-measurement paper. An earlier idea proposed a "Semantic Taint" fix with an NLI/entailment checker; we dropped it because defence papers face a higher bar and it was the weakest limb. If a stronger paper is wanted later, a *bounded* fix for one attack class could be a follow-up — not this paper.
- **No standalone impossibility theorem.** The real impossibility results (instruction/data separability, context-legitimacy) are already published. Our theory contribution is a *bounded reduction* (laundering-resistance ⇒ screener adversarial robustness) plus one measured assumption — not a headline theorem. The paper's weight rests on the **metric + attacks**.
- **Two primary targets only (RTBAS, AuthGraph).** ARGUS and others stay in related-work. We do not attack ARGUS; do not let the research-gap wording imply otherwise.

---

## 1. Ground truth about the code (verified)

- **AgentDojo is public and does most of the heavy lifting.** It already gives us: the agent pipeline, tools, 97 user tasks, 629 injection cases across 4 domains (banking, slack, travel, workspace), a formal (non-LLM) success check computed on environment state, and a benchmark runner with `--attack` and `--defense` flags. **We build on top of it; we do not rebuild an agent.**
- **RTBAS has no public code**, but the paper fully specifies the mechanism: a *dependency screener* using (a) an LM-as-a-judge and (b) attention-based saliency, which returns the *joined label of all relevant regions* and *masks/redacts* irrelevant ones. We reimplement this as a defence module on AgentDojo.
- **AuthGraph has no public code**, but its appendix publishes the **complete system prompts** for its three components (Graph Builder / Planner / Checker) plus its node types (input=trusted, observation=untrusted, decision/intermediate=inherited), edge types (DERIVE, EXTRACT, INVOKE), and rules. A separate group (FAVA, arXiv:2607.27267) already reimplemented it. We reimplement it from the published prompts.

**Consequence:** the real engineering cost is reimplementing two screening mechanisms on AgentDojo — not integrating three foreign codebases. Budget for this explicitly.

---

## 2. Phase 0 — Verification gates (Week 1, BEFORE any attack code)

These are go/no-go checks. Each produces a short written finding that later becomes part of the paper's threat-model / related-work / limitations. **Do not skip.**

- **V1 — Baseline numbers.** Read the FIDES and CaMeL papers directly and record their real task-completion figures and threat models (do not trust second-hand numbers). Confirms the soundness–utility trade-off we build the argument on.
- **V2 — RTBAS taint semantics (the critical one).** From the RTBAS paper, answer precisely: *when a tainted region is reworded/re-emitted by an agent on the next hop, is its taint re-derived from scratch each hop, or carried transitively?* If transitive, our **multi-hop re-emission** attack fails and we lean on the other three. Also confirm the "screener mistakes fail safe via masking" claim and what exactly it covers.
- **V3 — Reimplementation feasibility.** We already know: no public RTBAS/AuthGraph code; AuthGraph prompts are published. Decide reimplementation effort and lock a fidelity target (see §4).
- **V4 — Scoop check.** Read these recent, adjacent papers and write one line each on how we differ:
  - *Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents* (arXiv:2604.04035) — **uses the word "laundering"**; confirm it's a different mechanism (denial-feedback leakage, not label declassification).
  - *Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents* (arXiv:2606.26479) — adaptive-attack angle; confirm it doesn't already cover our screener attacks.
  - *FAVA* (arXiv:2607.27267) — reimplements AuthGraph; confirm it doesn't measure label integrity.
  - Choudhary et al. *How not to detect prompt injections with an LLM* (AISec 2025) — the backbone of our reduction; confirm it supports, not subsumes, our claim.
- **V5 — Extra target.** Skim PermissiveIFC (arXiv:2410.03055) and Wu/Cecchetti/Xiao IFC (arXiv:2409.19091); decide whether either is worth adding as a third screening target.

**Phase-0 exit criterion:** V2 answered, and reimplementation effort for at least RTBAS *or* AuthGraph estimated at ≤ 2 weeks. If neither is, the timeline changes (see §11) — flag it now, not in week 6.

---

## 3. Repository structure

```
provenance-laundering/
├── README.md
├── IMPLEMENTATION_PLAN.md          # this file
├── env/                            # environment + exact dependency pins
│   └── requirements.txt
├── pipeline/                       # the agent pipeline under test
│   ├── runner.py                   # wraps AgentDojo; runs one (task, attack, defence) config
│   └── trace.py                    # the structured trace object (see §8) — THE core data type
├── defenses/
│   ├── base.py                     # Defence interface: sees the trace, labels each item, allow/block
│   ├── rtbas.py                    # reimplemented dependency screener (LM-judge + attention)
│   ├── authgraph.py                # reimplemented dual-graph checker (from published prompts)
│   ├── fides.py                    # strict/deterministic baseline
│   └── camel.py                    # dual-LLM / capability baseline (or wrap AgentDojo's if present)
├── attacks/
│   ├── base.py                     # Attack interface: (task, injection slot) -> crafted payload
│   ├── multi_hop_reemission.py
│   ├── attention_bypass.py         # NOTE: needs an open-weights model
│   ├── attribution_forgery.py
│   └── label_join.py
├── metrics/
│   ├── lis_oracle.py               # counterfactual re-execution oracle (headline)
│   ├── asr.py                      # from AgentDojo's formal success check
│   ├── ser.py                      # did the payload pass the screener?
│   └── literal_baseline.py         # deterministic literal-value detector
├── experiments/
│   ├── configs/                    # one YAML per experiment (seeds, model, task set, attack, defence)
│   └── run_matrix.py               # runs the full attack×defence×task matrix
├── logs/                           # raw structured run logs (one JSON per run) — never edited by hand
├── analysis/
│   ├── build_tables.py             # logs -> the exact tables in the paper
│   ├── build_figures.py            # logs -> the exact figures
│   └── stats.py                    # cluster bootstrap, CIs (see §9)
└── paper/
    └── artifact_map.md             # which table/figure comes from which experiment+query (see §10)
```

The single most important design choice: **everything flows through one `Trace` object, and every run writes one immutable JSON log.** Tables and figures are *derived* from logs, never hand-entered. That is what makes the numbers reproducible and paper-defensible.

---

## 4. Phase 1 — Harness + reimplemented defences (Weeks 1–3)

**Goal:** run one agent task end-to-end, under a chosen attack and a chosen defence, and emit a complete trace.

Steps:

1. Stand up AgentDojo; reproduce one of its published attack/defence numbers to confirm the environment works. (Sanity anchor — if you can't reproduce their baseline, stop and fix the setup.)
2. Define the `Trace` (see §8) and make `pipeline/runner.py` emit it for every run.
3. Reimplement defences to a stated **fidelity target**. You are not claiming a bit-exact clone; you are claiming a *faithful* reimplementation. Write down, per defence, exactly what you implemented and what you approximated — this goes in the paper's appendix and protects you from "that's not really RTBAS" reviews.
   - **RTBAS:** LM-judge screener + attention-saliency screener; region masking; joined labels. Reproduce their reported clean-benign behaviour (low utility loss) before attacking it.
   - **AuthGraph:** the three components from the published prompts; parameter-source-level checking. Reproduce their ballpark (attack success low, ~76% completion) on clean AgentDojo before attacking it.
4. **Fidelity check:** on unattacked AgentDojo, each reimplemented defence should roughly match its paper's benign task-completion and clean-attack numbers. Log the gap. If you're far off, the reimplementation is wrong and any later attack result is meaningless.

**Phase-1 exit:** both reimplemented defences reproduce their papers' clean behaviour within a stated tolerance, and every run writes a full trace.

---

## 5. Phase 2 — The LIS oracle (Weeks 3–4) — build this BEFORE the attacks

LIS asks, per hop: *did the defence's trust label match the truth?* "Truth" comes from **counterfactual re-execution** — re-run the pipeline with the attacker's payload removed and see what actually changes.

Build:

1. **Counterfactual runner.** Given a run, produce a matched run with the payload excised and replaced by neutral filler.
2. **Two-tier oracle** (this resolves the "what is truth at a non-action step?" problem):
   - **Sink tier (high confidence):** at security-relevant actions, ground truth = does the *action* change when the payload is removed? Action-level divergence is far less noisy than text-level.
   - **Intermediate tier (lower confidence):** at hops that emit no action, use text-level divergence, and *label it as lower-confidence* in the output.
   - Report **LIS-sink** and **LIS-all** separately; **LIS-sink is the headline.**
3. **Filler robustness.** Use **n ≥ 3 distinct neutral fillers** per case; if the action changes across fillers *alone* (with no attack), that case is unusable for ground truth — drop it and log how many you dropped.
4. **Determinism.** Temperature 0, fixed seeds, n ≥ 5 seeds per case where a model is in the loop.
5. **Measure the oracle itself.** Report oracle reliability: agreement across seeds/fillers, and agreement with **human annotation on a 200-case subset (report Cohen's κ)**. If the oracle is noisy, the headline metric is noise — you must know this number.

**Phase-2 exit:** LIS-sink computable on a run, with a measured, acceptable oracle-reliability number. Pre-register the divergence threshold *before* looking at attack results.

---

## 6. Phase 3 — The four attacks (Weeks 4–6)

All attacks share one interface: input = (benign task + injection slot), output = crafted payload. Each targets a specific screener weakness.

1. **Multi-hop re-emission** (`multi_hop_reemission.py`) — payload designed so that after an intermediate agent rewords it, the defence treats the reworded text as fresh, agent-generated, trusted content. *Gated by V2:* if RTBAS tracks taint transitively, this won't work on RTBAS — keep it, but expect it to succeed mainly where taint is re-derived per hop.
2. **Attention-screener bypass** (`attention_bypass.py`) — content that steers the final action through a low-attention path, so the attention-saliency screener rates it unimportant. **Requires an open-weights model** (you need the attention weights). Note this constraint loudly: results here won't transfer to closed models. If RTBAS's attention screener uses a *trained* component that isn't released, this attack needs that piece rebuilt too — check in V3.
3. **Attribution forgery** (`attribution_forgery.py`) — payload that falsely asserts its own trusted origin, aimed at AuthGraph's reasoning-graph builder (which the paper itself admits can contain "manipulated attributions"). This is the natural AuthGraph attack.
4. **Label-join granularity** (`label_join.py`) — bury the malicious span inside a mostly-relevant block, so a region-level screener keeps the whole block. Aimed at RTBAS's region/joined-label mechanism.

**Phase-3 exit:** each attack runs against each applicable defence over the AgentDojo task matrix, and every run is logged with its trace, the defence's labels, the screener decision, and the executed action.

---

## 7. Phase 4 — Baseline, measurement, reduction (Weeks 6–7)

1. **Literal-value baseline** (`literal_baseline.py`) — at every security-relevant sink, extract literal argument values (URLs, emails, file paths, amounts) and check whether each appears (exact + fuzzy) in any untrusted input seen earlier. No model, no injection surface. It will catch many real attacks *and* it defines the **residual class**: attacks that transfer *no* literal value (the agent derived the malicious argument itself) — those are exactly the cases that still require model-based detection. Report this class explicitly; it's a headline honesty point.
2. **Compute all metrics** from the logs: ASR (AgentDojo's formal check), LIS-sink/LIS-all, SER, and residual class, per attack × per defence.
3. **The reduction, measured.** Don't hand-wave the theory. State it as a reduction ("any usable = declassifying → screener judges attacker-influenced text → known-unsolved") and back the one empirical assumption: instrument *conservative* propagation on AgentDojo and measure what fraction of its utility loss occurs on paths that actually reach a security-relevant sink. That number is the assumption your reduction rests on — report it, don't assume it.

**Phase-4 exit:** the main results table populated from logs; residual class quantified; the reduction's one empirical assumption measured.

---

## 8. The Trace object and per-run log (the "record for the paper")

This is the part that turns code into a publishable record. Every run writes **one immutable JSON file** to `logs/`. Minimum schema:

```json
{
  "run_id": "uuid",
  "timestamp": "iso8601",
  "config": {
    "model": "…", "seed": 0, "temperature": 0,
    "suite": "banking", "user_task_id": "…", "injection_task_id": "…",
    "attack": "attribution_forgery", "defense": "authgraph",
    "attack_params": { }, "code_commit": "git-sha"
  },
  "hops": [
    {
      "hop_index": 0, "agent_role": "retriever",
      "input_context_digest": "…", "output_text": "…",
      "contains_untrusted_source": true,
      "defense_label": "untrusted",            // what the defence THINKS
      "screener_decision": "declassify",       // keep | declassify | block
      "screener_reason": "…"
    }
  ],
  "final_action": { "tool": "send_money", "args": { "to": "attacker.com", "amount": 500 } },
  "attack_succeeded": true,                     // AgentDojo formal check → ASR
  "counterfactual": {
    "fillers": ["…","…","…"],
    "action_changed_per_filler": [true, true, false],
    "usable_for_ground_truth": true
  },
  "ground_truth_influence_per_hop": [true, false, ...],  // from counterfactual
  "label_correct_per_hop": [false, true, ...],           // defence_label vs ground truth → LIS
  "screener_evaded": true                                // → SER
}
```

Rules:
- **Never hand-edit a log.** If a run is wrong, fix the code and re-run.
- Every log records the **git commit** and the **exact config**, so any number in the paper is traceable to a reproducible run.
- `analysis/build_tables.py` reads `logs/` and emits the paper tables. If a number isn't produced by that script from a log, it doesn't go in the paper.

---

## 9. Statistical protocol (decide before seeing results)

- **Cluster at the execution level.** Transitions within one execution are correlated; treating them as independent inflates significance. Bootstrap by resampling **whole executions**, not hops.
- **Pre-register thresholds** (LIS divergence cutoff, "success" definitions) in writing before running the full matrix.
- Report **confidence intervals**, not just point estimates, on ASR / LIS / SER.
- Report **how many cases were dropped** (unusable counterfactuals) and why.

---

## 10. Paper artifact map (fill in `paper/artifact_map.md` as you go)

| Paper element | Produced by | From |
|---|---|---|
| Table 1 — ASR / LIS-sink / SER per attack × per defence | `build_tables.py::main_results` | `logs/` full matrix |
| Table 2 — Oracle reliability (seed/filler agreement, human κ) | `build_tables.py::oracle` | 200-case annotation subset |
| Table 3 — Residual class size per attack | `build_tables.py::residual` | literal-baseline runs |
| Fig 1 — Architecture / laundering surface | static (already made) | — |
| Fig 2 — LIS vs ASR (labels dishonest even when blocked) | `build_figures.py::lis_vs_asr` | `logs/` |
| Appendix A — reimplementation fidelity vs published numbers | `build_tables.py::fidelity` | clean-run logs |
| Appendix B — payload-survival pilot (optional) | `build_figures.py::survival` | 8-cell pilot first |

Each row is a promise: that number/figure is regenerated by a script from logged runs.

---

## 11. Timeline and go/no-go gates

Assumes reimplementation (not cloning), which V3 confirms.

- **Week 1:** Phase 0 gates (V1–V5) + AgentDojo up + one baseline reproduced + **pick a target venue** and work backward from its deadline/format (security workshop or conference; page limit, anonymisation, and artifact-evaluation rules all change what we cut).
  - **GATE A:** V2 answered; ≥1 target reimplementable in ≤2 weeks. *If not → switch to the 12–16 week plan and tell the guide now.*
- **Weeks 2–3:** reimplement RTBAS + AuthGraph to fidelity target.
  - **GATE B:** both reproduce clean-behaviour numbers within tolerance. *If not, attack results are meaningless — fix first.*
- **Weeks 3–4:** LIS oracle + measured oracle reliability.
  - **GATE C:** oracle κ acceptable. *If oracle is noise, the headline metric is noise — do not proceed to claims.*
- **Weeks 4–6:** four attacks over the matrix.
- **Weeks 6–7:** literal baseline, all metrics, reduction assumption measured.
- **Week 7:** responsible disclosure e-mails to RTBAS (CMU) and AuthGraph (UVA) authors; document dates.
- **Week 8:** write-up; tables/figures regenerated from logs; freeze.

---

## 12. Risks and pre-agreed pivots

| Risk | Likely? | Pivot |
|---|---|---|
| RTBAS tracks taint transitively | ~25% | Multi-hop attack fails on RTBAS; lean on label-join + attention-bypass; keep multi-hop for the controlled pipeline where taint is per-hop |
| Reimplementations can't match clean numbers | ~25% | Extend Phase 1; report as a fidelity limitation; consider using FAVA's AuthGraph reimplementation approach as a reference |
| LIS oracle too noisy | ~15% | Fall back to action-type-only divergence (sink tier only); report reduced precision; drop LIS-all |
| A scoop paper (V4) overlaps | ~15% | Re-position around the specific gap it leaves (e.g. nobody measures *label* integrity, only attack success) |
| Attention-bypass needs unreleased trained screener | ~30% | Restrict that attack to the open-weights setting; state the limitation; the other 3 attacks don't need it |

---

## 13. Responsible disclosure + release

- E-mail the RTBAS (CMU: Zhong et al.) and AuthGraph (UVA: Wang, Li, Tian) authors around Week 7 with findings; keep dated records. Most security venues require this.
- Plan to release the **attack suite + LIS harness** as the public artefact (matches your "Expected Outcomes: public artefact" slide).

---

### The one-paragraph version

Build on AgentDojo. Reimplement RTBAS's screener and AuthGraph's dual-graph checker on top of it (no public code exists; AuthGraph's prompts are published, so it's feasible). Build the LIS oracle *first* via counterfactual re-execution, and measure the oracle's own reliability. Then run four laundering attacks across the attack×defence×task matrix, logging every run as immutable JSON. Derive every paper table/figure from those logs with a script. Add a deterministic literal-value baseline to define the residual class, back the reduction with one measured assumption, disclose to the authors, and release the harness. Gate the whole thing on Phase 0 — especially whether RTBAS re-derives taint per hop, which decides if attack #1 works against it.
