# Coding Plan — Fastest Path to Submission (LaunderLens)

**Goal:** reach a *defensible, publishable result* on the shortest path, then expand.
**Headline contribution (the un-scooped part):** Label Integrity — a defence can be
"right for the wrong reason" or fail because a label went dishonest, and standard
attack-success metrics are blind to it. LIS measures it.

**Positioning discipline (every coding session):** before building a component,
re-check the closest papers (esp. arXiv:2606.26479 adaptive-eval, MemLineage, the
memory-laundering paper) and make sure what you build measures or attacks something
they don't. Write one line in `paper/differentiation.md` each time.

---

## The strategy in one line

Build **LIS + ONE defence (AuthGraph) + TWO attacks** first → get a real result →
**go/no-go checkpoint** → only then expand to the second defence, more attacks, baseline.
This hits a decision point in ~3–4 weeks instead of ~8.

---

## Phase 1 — Foundation  (≈ now → a few days)

Status: AgentDojo runs locally ✓ · `pipeline/trace.py` built ✓.

- [ ] `pipeline/runner.py` — wrap one AgentDojo run; capture each hop into a `Trace`; save one JSON to `logs/`.
- [ ] Record `code_commit` (git SHA) and full config in every trace.
- [ ] Run it on `banking/user_task_0` (no attack, no defence) → confirm one real log file appears.

**Milestone 1:** one real logged run from an actual task, not the demo.

---

## Phase 2 — LIS oracle  (the crown jewel — build BEFORE defences)

Build on the plain pipeline first, so you know the measurement works before adding complexity.

- [ ] `metrics/lis_oracle.py` — counterfactual re-execution: given a run, produce a matched run with the payload removed / replaced by neutral filler.
- [ ] Two-tier truth:
  - **Sink tier (headline):** at a security-relevant action, ground truth = does the action change when the payload is removed?
  - **Intermediate tier (lower confidence):** text-level divergence at non-action hops; mark as lower-confidence.
- [ ] `n ≥ 3` distinct fillers per case; if the action changes across fillers *alone* (no attack), drop that case as unusable — log how many dropped.
- [ ] Temperature 0, fixed seeds, `n ≥ 5` seeds where a model is in the loop.
- [ ] **Measure the oracle itself:** agreement across seeds/fillers + human agreement (Cohen's κ) on a 200-case subset. Write the κ into the repo.
- [ ] Pre-register the divergence threshold in writing before you look at any attack result.

**Milestone 2:** LIS-sink computable on a run, with a measured, acceptable oracle κ.
*(If κ is bad, the metric is noise — fix before proceeding. This is a hard gate.)*

---

## Phase 3 — ONE defence: AuthGraph  (fastest faithful reimplementation)

Why AuthGraph first: (a) 2606.26479's adaptive eval did **not** cover it; (b) its full
system prompts are published, so reimplementation is realistic; (c) it's the current SOTA.

- [ ] `defenses/base.py` — interface: sees the trace, labels each item, returns keep/declassify/block.
- [ ] `defenses/authgraph.py` — reimplement the three components from the published prompts:
  - Graph Builder (injected reasoning graph, IRG) — node types input=trusted / observation=untrusted / decision+intermediate=inherited; edges DERIVE / EXTRACT / INVOKE.
  - Planner (authorization graph from clean context).
  - Checker (graph alignment: tool-name + parameter-source).
- [ ] **Fidelity check:** on clean AgentDojo, reproduce its ballpark (low attack success, ~76% completion on a capable model). Log the gap. Document exactly what you approximated (goes in the paper appendix).

**Milestone 3:** AuthGraph reimplemented; clean behaviour matches the paper within a stated tolerance.

> Note: AuthGraph's benign numbers assume a capable model. On a local 8B they'll be lower.
> Use the local model to *build and debug*; plan a small amount of GPT-4o-class credits (or
> university compute) for the **headline** result runs so they're comparable to the paper.

---

## Phase 4 — TWO attacks + first result

- [ ] `attacks/base.py` — interface: (task, injection slot) → crafted payload.
- [ ] `attacks/attribution_forgery.py` — payload that falsely asserts a trusted origin; aimed at AuthGraph's reasoning-graph builder (which the paper admits can carry manipulated attributions).
- [ ] `attacks/label_join.py` — bury the malicious span in a mostly-relevant block so region-level checking keeps the whole block.
- [ ] `metrics/asr.py` (from AgentDojo's formal check) and `metrics/ser.py` (did the payload pass the checker?).
- [ ] Run attribution-forgery + label-join × AuthGraph over a small AgentDojo slice; log every run.
- [ ] `analysis/build_tables.py` — first table from logs: ASR, LIS-sink, SER per attack.

**Milestone 4:** your first real result table, produced entirely from logs.

---

## ⭐ GO / NO-GO CHECKPOINT  (read the numbers here)

Decide before expanding:

- **Strong signal:** LIS reveals label dishonesty that ASR misses (e.g. attacks blocked but labels wrong, or a laundering path where the label flips and the action goes through). → **You have the paper.** Proceed to Phase 5.
- **Weak signal:** ASR low *and* LIS shows labels basically honest. → **Re-scope now**, not in two months. Options: pivot LIS to a pure methodology paper across CaMeL/FIDES/RTBAS/AuthGraph ("measuring right-for-wrong-reasons"), or change the attack surface. We decide together based on the numbers.

This checkpoint is the whole point of the speed ordering: you learn if the idea works in ~3–4 weeks.

---

## Phase 5 — Expand only what the result needs

Add in this order, each strengthening the same finding:

- [ ] `defenses/rtbas.py` — second defence (LM-judge + attention screener). Note: the attention attack needs the local open-weights model.
- [ ] `attacks/multi_hop_reemission.py` and `attacks/attention_bypass.py`.
- [ ] `metrics/literal_baseline.py` — deterministic literal-value detector → defines the residual class.
- [ ] More AgentDojo suites (start banking → add workspace, travel, slack).
- [ ] `defenses/fides.py`, `defenses/camel.py` as baselines (or wrap AgentDojo's if present) — for the utility/safety trade-off framing.
- [ ] Full attack × defence × suite matrix via `experiments/run_matrix.py`.

---

## Phase 6 — Write + reproduce + submit

- [ ] `analysis/build_tables.py` + `build_figures.py` regenerate every table/figure from `logs/`. Nothing hand-typed.
- [ ] `analysis/stats.py` — cluster bootstrap at the **execution** level; confidence intervals; report dropped-case counts.
- [ ] `paper/artifact_map.md` — each table/figure ↔ the exact experiment + script that makes it.
- [ ] `paper/differentiation.md` — the running list of how you differ from each near paper (2606.26479, MemLineage, memory-laundering, NeuroTaint, Agent-Sentry).
- [ ] Responsible-disclosure emails to RTBAS (CMU) and AuthGraph (UVA) authors; keep dates.
- [ ] Pick target venue in week 1 and work backward from its deadline/format.

---

## Timeline (aggressive but honest)

| Week | Target |
|---|---|
| 1 | `runner.py` + first real log · LIS oracle started · read 2606.26479 in full · pick venue |
| 2 | LIS oracle done + oracle κ measured (Milestone 2) |
| 3 | AuthGraph reimplemented, clean-behaviour matched (Milestone 3) |
| 4 | Two attacks + first result table (Milestone 4) → **GO/NO-GO** |
| 5–6 | Expand (RTBAS, other attacks, baseline, more suites) |
| 7 | Headline runs on a capable model · disclosure emails |
| 8 | Write-up · regenerate everything from logs · freeze · submit |

Contingency: if AuthGraph reimplementation slips past week 3, or oracle κ is bad, the
timeline stretches — surface it at the weekly check, don't absorb it silently.

---

## What differentiates you, kept front-and-centre

Every session, the test is: *does this component measure or attack something
2606.26479 / MemLineage / the memory-laundering work did not?* Your durable answers:

1. **Label honesty as a metric (LIS)** — they measure attack success; you measure whether the defence's labels told the truth.
2. **AuthGraph as a target** — the adaptive-eval paper skipped it.
3. **Live single-task declassification** — not the memory / cross-session setting the "laundering" papers occupy.
4. **Behavioral label integrity** (counterfactual) — not MemLineage's cryptographic label integrity.

If a component doesn't sit inside one of those four, it's not your contribution — it's plumbing.

---

### One-paragraph version

Build the LIS oracle and one reimplemented defence (AuthGraph) first, get a real result
from two attacks in ~3–4 weeks, and stop at a go/no-go checkpoint to see whether label
honesty reveals something attack-success misses. If yes, expand to RTBAS, more attacks,
and the baseline; if no, re-scope early. Everything flows through immutable per-run logs,
every number regenerates from them, and every component must measure or attack something
the nearest existing papers do not.
