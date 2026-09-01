# LaunderLens — Closure Plan (from here to submission)

_Written 2026-08-28. This is the "finish the project" plan: everything remaining,
in order, with what each step produces and what it costs. When every box here is
ticked, the project is DONE and the paper goes out._

**Current standing (honest):**
- Phases 1–4 complete, GO/NO-GO passed with a strong signal.
- Phase 5 checklist ticked, but with uneven evidence depth (see Stage 1).
- Phase 6 (write-up) not started.
- Headline finding, as it stands: **AuthGraph's verbatim-match shortcut produces
  dishonest "trusted" labels under attack (53 dishonest cases, zero exceptions);
  RTBAS holds (zero dishonest, across banking + slack, n=3-9); Fides and CaMeL
  hold but have only n=1 each.**

---

## The story this plan is building toward

> Standard evaluations ask "was the attack blocked?" We ask "was the defence's
> own label honest?" — and show these come apart. AuthGraph's verbatim-match
> shortcut launders attacker-controlled values into "trusted" labels. RTBAS,
> Fides and CaMeL don't have that shortcut and hold. **But** the shortcut is not
> arbitrary: it exists to avoid over-blocking, and the defences that avoid
> AuthGraph's failure pay for it in legitimate actions blocked. LIS is what makes
> this trade-off visible, because ASR alone cannot see it.

That last sentence is the paper's real contribution, and Stage 2 is what proves
it. Everything else here is support.

---

## Stage 0 — Two decisions to make first (blocking, not codeable)

These gate later stages. Make them this week.

- [ ] **Venue + deadline.** Still TBD since week 1. Candidates: AISec, SaTML.
      The deadline sets page limits, artifact requirements, and how much of
      Stage 4 is affordable. *Everything downstream is scheduled off this date.*
- [ ] **API budget for the capable-model pass (Stage 4).** Yes/no, and how much.
      If "no", Stage 4 becomes a written limitation instead of an experiment —
      that is survivable but weakens the paper; decide deliberately, not by
      default.
- [ ] **Patent track: recommend DROPPING.** LIS is a software measurement method
      built on counterfactual re-execution, a mechanism with clear prior art
      (NeuroTaint uses the same mechanism — see `differentiation.md` §2).
      Method claims of this shape are hard to sustain, and publishing generally
      destroys patentability in most jurisdictions, so the two tracks conflict
      directly. **If a patent genuinely matters, talk to the university's
      tech-transfer office BEFORE submitting anywhere.** The figures produced in
      Stage 5 serve a disclosure document just as well as a paper, so this
      decision does not change any engineering work below — only its timing.

---

## Stage 1 — Level the evidence (local model, no new money)

Right now four defences sit at wildly different evidence depths. A reviewer will
notice. Bring Fides and CaMeL up to the same bar RTBAS already cleared.

- [ ] **1.1 — Fides + CaMeL across the banking matrix.**
      All 9 attack/variant combos × both new defences, seeds=3.
      ```
      python experiments/run_phase4.py --attack attribution_forgery --defense fides --seeds 3
      python experiments/run_phase4.py --attack label_join           --defense fides --seeds 3
      python experiments/run_phase4.py --attack multi_hop_reemission --defense fides --seeds 3
      # ...same three for --defense camel
      ```
      *Cost:* ~18 cells × 13 runs — several hours of local compute, no money.
- [ ] **1.2 — Fides + CaMeL on slack.** Both variants × both defences, seeds=3.
      ```
      python experiments/run_phase4.py --attack slack_invite_redirect --variant full_replacement --defense fides --seeds 3
      # ...and dual_contact, and --defense camel
      ```
- [ ] **1.3 — Add both to `run_matrix.py`'s dimensions.** `ALL_DEFENSES` is
      currently `["authgraph", "rtbas"]` only. Add `fides`, `camel` so the
      unified cross-suite table covers all four.
- [ ] **1.4 — Rescore + confirm no regressions.**
      `python analysis/rescore_phase4.py experiments/results/phase4_*.json`
      Banking's 45/13 subtotal must stay unchanged. Record the new totals.

**Exit criterion:** every one of the four defences has ≥3 seeds across both
suites, so the results table has no "n=1" asterisks in it.

**Expected outcome, stated in advance (pre-registration discipline):** Fides and
CaMeL are predicted to HOLD, because current attacks target AuthGraph's
verbatim-match shortcut specifically, which neither has. *If they hold, that is
the result — do not go hunting for a way to break them after seeing this.* If
one unexpectedly launders, that is a finding worth a section of its own.

---

## Stage 2 — The utility / over-blocking measurement (the missing half)

**This is the highest-value remaining work.** It completes the trade-off story
and needs no new attacks and no API budget.

The insight: a defence that blocks everything is trivially "secure" and useless.
AuthGraph's shortcut probably exists *precisely* to avoid RTBAS-style
over-blocking — which makes the vulnerability a deliberate trade-off, not a bug.
Proving that turns "AuthGraph is broken" into "here is the real tension in
declassification design."

- [ ] **2.1 — `metrics/utility_score.py`.** Given a CLEAN trace (no attack) and a
      defence, count: how many legitimate, security-relevant actions did the
      defence BLOCK? Report as a false-positive / over-blocking rate.
      Mirror the existing `ser_score.py` shape so it slots into the pipeline.
- [ ] **2.2 — `experiments/run_utility.py`.** Replay every clean trace already in
      `logs/` (164 available, no new agent runs needed) through all four
      defences; write per-defence over-blocking rates to
      `experiments/results/utility_*.json`.
      *Cost:* defence-screening LLM calls only — no agent re-runs. Cheap.
- [ ] **2.3 — Sanity-check against the known hint.** `rtbas.py`'s own smoke test
      blocks `send_money` even on the CLEAN banking case (the legitimate IBAN
      arrives via untrusted `read_file`). Confirm whether that reproduces on real
      clean traces. **If it does, RTBAS's perfect label-honesty record has a
      price tag, and that is the paper's central trade-off.** If it does NOT
      reproduce, say so plainly and drop the trade-off framing — do not force it.
- [ ] **2.4 — Build the 2×2 that makes the point.**
      | | Catches attacks (LIS) | Preserves utility |
      |---|---|---|
      | AuthGraph | ✗ | ✓ (permissive — why it fails) |
      | RTBAS | ✓ | ? ← 2.2 answers this |
      | Fides | ? | ? |
      | CaMeL | ? | ? |

**Exit criterion:** a defensible statement of the form "defence X achieves label
honesty Y at a cost of Z% of legitimate actions blocked," for all four.

---

## Stage 3 — Statistical rigor + remaining scope debts

Small, known debts already flagged in `differentiation.md`. Clear them before
numbers freeze.

- [ ] **3.1 — `analysis/stats.py`.** Cluster bootstrap at the execution level;
      confidence intervals on every headline number; report dropped-case counts
      explicitly. (Phase 6 item in `CODING_PLAN.md`, never built.)
- [ ] **3.2 — Real fillers.** `differentiation.md` §3.3 TODO: `DEFAULT_FILLERS`
      are hand-written to satisfy the locked policy; the policy prefers text
      sampled from the suite's own environment data. Swap them, then re-run the
      oracle on a sample to confirm verdicts don't shift. *If verdicts DO shift,
      that is important and must be reported, not quietly fixed.*
- [ ] **3.3 — Extend oracle κ.** Currently 24 fully-evidenced cases (κ=1.000).
      Rate a fresh batch from the Stage 1 runs to push n higher.
- [ ] **3.4 — Decide travel suite: in or out.** Untouched, local-only, would add
      a 4th domain. Cheap generality win *if* time allows; explicitly cut it if
      not. Do not leave it ambiguous.

---

## Stage 4 — Capable-model pass (gated on Stage 0 budget decision)

Closes the biggest reviewer objection: *"this only breaks because your model is
weak."*

- [ ] **4.1 — Wire in the API model.** Pipeline is already model-agnostic —
      `--model-id` swap, not new code. Verify one smoke run end-to-end first.
- [ ] **4.2 — Re-run the headline cells only.** Banking's 9 combos × AuthGraph +
      RTBAS, seeds=3, plus slack's 4 cells. *Not* the full four-defence matrix —
      spend credits where the claim lives.
- [ ] **4.3 — Report both.** Local vs capable-model numbers side by side. If the
      finding holds on both, that is the strongest possible version of it.

**If budget is "no":** write §"Local-model limitation" honestly — state that all
numbers use `qwen2.5:14b`, that AuthGraph/RTBAS report theirs on GPT-4o-class
models, and that the mechanism we identify (verbatim string matching) is
model-independent by construction. Weaker, but defensible.

---

## Stage 5 — Figures and tables (all regenerated from logs, nothing hand-typed)

Serves the paper and any patent/disclosure document equally.

- [ ] **5.1 — `analysis/build_tables.py`.** Regenerates every results table from
      `experiments/results/*.json`. No hand-typed numbers anywhere, ever.
- [ ] **5.2 — `analysis/build_figures.py`.** Produces:
      - **Fig 1 — The mechanism.** Diagram: attacker value planted in a legitimate
        document → AuthGraph's verbatim match sees it "sourced correctly" →
        labels it trusted → laundering. *This is the paper's money figure.*
      - **Fig 2 — ASR vs LIS, per defence.** The core "these come apart" plot:
        cases where the attack was blocked but the label was still dishonest.
      - **Fig 3 — Security/utility trade-off scatter.** Label honesty (Stage 2)
        on one axis, legitimate actions preserved on the other; four defences
        plotted. **The paper's thesis in one image.**
      - **Fig 4 — Cross-domain consistency.** Banking / slack (/ travel), showing
        the finding is structural, not domain-specific.
      - **Fig 5 — Oracle reliability.** κ and the counterfactual-agreement data,
        for the methods section.
- [ ] **5.3 — `paper/artifact_map.md`.** Every table/figure ↔ the exact
      experiment + script that regenerates it. Reviewers ask for this.

---

## Stage 6 — Write

Sections that need NO further experiments — start these in parallel with Stage 1,
today. Do not wait for data to begin writing.

- [ ] **6.1 — Related work / differentiation.** `paper/differentiation.md` is
      already most of this; it needs shaping into prose, not new research.
- [ ] **6.2 — Methods.** LIS definition, the counterfactual oracle, filler
      policy, the pre-registered `actions_differ` rule, oracle κ.
- [ ] **6.3 — Reimplementation appendix.** Every APPROX call across all four
      defences (`differentiation.md` §3.4a, §3.6, §3.6a, §3.6b). This is a
      credibility asset — it shows the work is auditable, not hand-waved.
- [ ] **6.4 — Results.** Blocked on Stages 1–4.
- [ ] **6.5 — Discussion.** The trade-off argument, and a concrete
      defence-design recommendation: what should AuthGraph do instead of the
      verbatim shortcut? Cheap to write, materially raises the contribution.
- [ ] **6.6 — Limitations.** Post-hoc replay across all four defences; local
      model (if Stage 4 doesn't happen); single task per suite; workspace paused
      on model capability. **State these before a reviewer finds them.**

---

## Stage 7 — Ship

- [ ] **7.1 — Responsible disclosure emails.** AuthGraph (UVA) and RTBAS (CMU)
      authors; also Fides (Microsoft) and CaMeL (Google DeepMind) if their
      results appear. **Keep dates** — reviewers ask, and it is the right thing
      to do regardless.
- [ ] **7.2 — Freeze.** Tag the commit. Every number in the paper regenerates
      from that tag.
- [ ] **7.3 — Artifact package.** Repo + `artifact_map.md` + a README that runs
      the whole thing from clean.
- [ ] **7.4 — Submit.**

---

## Recommended order (parallelizes the waiting)

1. **Now:** Stage 0 decisions + start Stage 6.1/6.2/6.3 writing.
2. **Background:** Stage 1 runs (long, local, unattended).
3. **Then:** Stage 2 — the highest-value remaining experiment.
4. **Then:** Stage 3 debts; Stage 4 if budget allows.
5. **Last:** Stage 5 figures, Stage 6.4–6.6, Stage 7.

**Definition of done:** every box ticked, every number regenerable from logs by
script, disclosure emails sent, submitted. That is closure.

---

## What could still change the story (watch for these)

- **Stage 2 shows RTBAS does NOT over-block.** Then the trade-off framing dies
  and the paper is straightforwardly "AuthGraph has a specific flaw." Still
  publishable, less interesting. Report it honestly either way.
- **Fides or CaMeL launders in Stage 1.** Becomes a section of its own; strengthens
  the general claim beyond a single defence.
- **The capable model changes the result.** Most likely as *higher* ASR (a
  stronger agent follows injected instructions more competently). Report both.
- **Nothing breaks anywhere and everything over-blocks.** Then the real finding
  is "current declassification defences are either dishonest or unusable" — which
  is a fine paper, arguably a better one.
