# Differentiation & Scope Notes

_Running document: how LaunderLens differs from the nearest existing work, and honest
scope limitations we state up front rather than let a reviewer discover. Update this
file every time a new near-paper is found or a new design decision needs justifying._

---

## 1. The core differentiation (headline)

**Everyone else measures: "did the attack get blocked?" We measure: "was the
defence's own label honest?"**

A defence can reach the *correct outcome* (block an attack) via an *incorrect
internal reasoning path* (a wrong trust label) — right answer, wrong reason. This
matters because the same wrong label produces the *wrong* outcome under a
slightly different attack or deployment. Standard attack-success metrics cannot
see this; our Label Integrity Score (LIS) can, because it checks the label
against ground truth rather than only checking the final action.

---

## 2. Nearest papers, and exactly how we differ

### arXiv:2606.26479 — "Adaptive Evaluation of Out-of-Band Defenses" (Narisetty et al., June 2026)
- **What it does:** runs adaptive, defence-aware attacks against CaMeL, FIDES, Progent,
  RTBAS, and FORGE on AgentDojo. Found these defences mostly *hold* under adaptive attack.
- **How we differ:**
  1. It measures **attack success only** — never label correctness. Our LIS is a
     different instrument entirely: it doesn't ask "did the action get blocked,"
     it asks "was the label the defence assigned along the way actually true."
  2. It does **not cover AuthGraph** (published after/concurrent with their work).
  3. It's a pure **attack evaluation**; ours is an **attack + measurement** paper,
     with the measurement (LIS) as the headline, un-scooped contribution.

### NeuroTaint / "Ghost in the Agent" — counterfactual-based taint detection
- **What it does:** uses counterfactual re-execution (remove content, see if the
  outcome changes) to find attacks — i.e., to answer "is this content dangerous?"
- **How we differ (same mechanism, different question, different target):**
  NeuroTaint interrogates the **content** to find danger. We interrogate the
  **defence's verdict** to find dishonesty. We don't isolate the payload's effect
  independent of a defence — we ask whether *the defence's label*, given
  everything the defence actually did, was honest. NeuroTaint has no defence
  label to check in the first place; it was never auditing anyone's claim.
  One-liner: *"NeuroTaint uses counterfactuals to find attacks; we use
  counterfactuals to find dishonest labels inside defences — we audit the
  auditor."*

### Memory provenance laundering / PPMF (untitled paper found via search)
- **What it does:** identifies "provenance laundering" as untrusted external
  observations rewritten into persistent agent **memory** as trusted user history.
- **How we differ:** same core phrase, different setting. This is the
  **memory / cross-session** laundering problem. Ours is the **live, single-task
  pipeline** — the declassification/screening step within one run, not memory
  written across sessions.

### MemLineage (arXiv:2605.14421)
- **What it does:** "label integrity" via **cryptographic signatures** on memory
  entries — makes labels tamper-*proof*, in the memory setting.
- **How we differ:** same term ("label integrity"), completely different
  mechanism and question. MemLineage asks "can this label be tampered with?"
  (cryptographic, preventive). We ask "is this label *true*?" (behavioral,
  diagnostic, via counterfactual re-execution). We measure truthfulness; they
  enforce tamper-resistance. Different question, different setting (live
  pipeline vs. memory), different mechanism (behavioral vs. cryptographic).

### "From Agent Traces to Trust" survey (arXiv:2606.04990)
- **What it does:** states as established background that "unsafe behavior can
  arise from influence, not content alone" — i.e., the general insight that
  motivates our work is now known background, not itself a novel claim.
- **How we differ:** we don't claim the *insight* is new — we claim the
  **measurement** (LIS) and its application to declassification-style defences
  (RTBAS, AuthGraph) is new. Cite this survey to establish the motivating
  insight is well-founded, not ours to claim.

### Agent-Sentry, APPA, AuthSelect (adjacent defence/IFC papers)
- Each proposes its own labeling/declassification mechanism. None of them
  **measure whether their own or another system's labels are honest** using a
  behavioral ground-truth test. To be re-confirmed with a closer read before
  final submission — flagged as still-open verification, not yet fully checked
  line-by-line against LIS's specific method.

---

## 3. Known, accepted scope limitations (state these before a reviewer finds them)

### 3.1 Defence-in-the-loop counterfactuals (not isolating the payload alone)
Our counterfactual re-execution (removing/replacing the payload) re-runs the
**entire pipeline, including the defence itself**. For graph-based defences
(AuthGraph), this means the defence's own reasoning artifact (its IRG) is
rebuilt on the filler-substituted trace, not held fixed.

We do **not** isolate "the payload's direct effect on the base agent" from "the
payload's effect as mediated by the defence's own reasoning" — we measure the
two **jointly**. This is deliberate: our research question is whether the
**defence's label** is honest given everything the defence actually does when
deployed, not what a defence-free agent would do.

LIS-sink (checked only at the final security-relevant action) is reported as
the headline specifically because this entanglement compounds at earlier,
intermediate hops — which is also why LIS-all is reported separately and
flagged lower-confidence.

### 3.2 The counterfactual test defines "reality" for our purposes (not circular, but must be stated)
We do not appeal to a separate, independent ground truth. The counterfactual
IS how we define whether a payload was influential: if removing it changes the
security-relevant action, it was influential; if not, it wasn't. This must be
stated explicitly in methods, or it reads as circular ("we define truth by our
own test") rather than as the intentional, standard use of counterfactual
reasoning that it is.

### 3.3 Filler policy (locked; do not change without updating this file)
A filler is real, benign text drawn from the same suite's own environment data
(or, currently, hand-written text satisfying the same constraints — see TODO
below), matched to the original payload within ±15% token length, containing
no imperatives, no second-person instructions, and no reference to accounts,
addresses, or actions. A fixed pool of 3 fillers is used, prepared **before**
any results are examined.

**TODO before final numbers:** current `DEFAULT_FILLERS` in
`metrics/counterfactual.py` are hand-written to satisfy this policy
(verified programmatically — no forbidden words, correct length). They should
be replaced with text sampled from the suite's own real environment data
before headline results are reported, per the policy's stricter preference.

### 3.4 AuthGraph reimplementation — from published prompts, not released code
AuthGraph's authors state they will open-source their implementation, but at
the time of our reimplementation no public code existed. Our
`defenses/authgraph.py` is built directly from the system prompts published in
the paper's Appendix A (Graph Builder, Planner, Checker) and the three-layer
detection logic described in Section 3.4. Any deviation from the original is
flagged inline in the code with `APPROX`. We report a fidelity check (does our
reimplementation match the paper's reported clean-behaviour numbers within a
stated tolerance) before using it for headline results.

### 3.5 RTBAS mechanism — confirmed, shapes which attacks apply (Phase 0 V2 gate)
Read directly from the RTBAS paper (arXiv:2502.08966): RTBAS screens taint
**per-action**, not transitively through the whole history — this is the
paper's central design choice, explicitly built to avoid the "label creep"
problem of traditional taint propagation. Consequence: our **multi-hop
re-emission** attack does not straightforwardly apply to RTBAS (there is no
transitively-carried taint to re-emit). RTBAS's actual attack surface is its
**dependency screener's relevance/label-join judgment** — which the paper
itself concedes can make mistakes ("Screener Mistakes" section). Therefore:
- **attention-screener bypass** and **label-join granularity** attacks target RTBAS.
- **multi-hop re-emission** and **attribution forgery** target AuthGraph instead.

---

## 4. Candidate finding surfaced during Phase 3 build (not yet run live — flag, don't overclaim)

While reimplementing AuthGraph's Layer 3 (Parameter Source Check), we noticed a
possible instance of what AuthGraph's own paper calls **"same-observation
pollution"** — a limitation the original authors explicitly acknowledge and
scope out of their evaluation (Discussion, "Known limitations," point 1).

**The mechanism:** AuthGraph's `observation_direct` check verifies a parameter
value came from the *correct tool's observation* — but does not verify that
observation itself wasn't tampered with. In our banking scenario, the
attacker's payload sits **inside the same bill file** that legitimately
contains the real IBAN. If the attacker's fake IBAN is planted verbatim in
that same document, a naive string-match check could pass it as "legitimately
sourced from read_file," because technically, it is — the document itself is
what's compromised, not the provenance link.

**Status: a candidate laundering surface, not yet demonstrated live.** This was
noticed during offline/mock-LLM testing of the reimplementation, not on a real
model run. Before this becomes a claim in the paper, it needs:
1. A live run against the real (LLM-backed) AuthGraph reimplementation, not
   the mock-LLM smoke test.
2. Confirmation that a real attack payload can actually be crafted to exploit
   this path (vs. being caught by Layer 3's LLM-judgment fallback, which is
   the layer designed to catch exactly this via injection-sentence quoting).
3. If confirmed, this maps onto our **attribution forgery** attack category —
   it would be a concrete instance of it against AuthGraph specifically.

---

## 5. One-line differentiation summary (for abstract / related-work framing)

*Existing evaluations of provenance-based agent defences (including the most
recent adaptive evaluation) ask only "was the attack blocked?" — a question
that cannot distinguish a defence that is genuinely sound from one that merely
got lucky. We introduce the Label Integrity Score, which behaviorally verifies
— via controlled counterfactual re-execution — whether a defence's own trust
labels are honest, and apply it to real attacks against a faithful
reimplementation of AuthGraph (and, pending Phase 5, RTBAS), revealing
label-laundering even in cases attack-success metrics would score as fully
secure.*

### 3.4a AuthGraph reimplementation — explicit engineering judgment calls

The AuthGraph paper describes the system in prose + publishes the Planner/Checker
prompts, but leaves several implementation details unspecified. Every place we had
to make a call is logged here, so the reimplementation is auditable and no hidden
choice can be mistaken for the original authors' design.

1. **Verbatim-match shortcut applied to BOTH source categories.**
   The paper defines two parameter-source categories (verbatim-copied vs.
   reasoning-derived). It does NOT specify whether the "is this value literally
   present in the source observation?" fast-path check applies to both, or only to
   the verbatim category. We apply it to **both**: if a parameter value appears
   verbatim in its declared source observation, we treat it as sourced (allow) and
   do not invoke the LLM judge. Rationale: restricting the shortcut to only the
   verbatim category caused **false positives on entirely clean data** (a
   legitimate IBAN that was literally present in the bill was flagged as injection
   by the local-model judge). This may make our reimplementation slightly MORE
   PERMISSIVE than the original in ambiguous cases. Flagged as `APPROX` in code.
   Crucially, this does NOT weaken the laundering finding: when the source
   observation is itself poisoned (same-observation pollution), the verbatim match
   correctly passes the laundered value as "sourced" — the exact behaviour LIS is
   designed to expose.

2. **First-action / empty-observation handling.**
   The paper does not specify Layer-3 behaviour when a parameter's declared source
   tool has not yet produced an observation (e.g. the very first action in a run).
   We skip the check gracefully (allow) in that case, since a value cannot have
   been influenced by an observation that does not yet exist. This is a bug-fix to
   our own implementation, not a change to AuthGraph's logic.

3. **Non-existent / "none" source tools.**
   The Planner (local model) sometimes emits a source_tool of "none" or an empty
   list. The paper assumes a well-formed plan. We skip the source check gracefully
   in this case rather than false-flag, and note it as a Planner-quality gap
   attributable to the weaker local model, not to AuthGraph's design.

4. **Local model vs. the paper's model.**
   AuthGraph's reported numbers use a GPT-4o-class model for both the agent and the
   Planner/Checker. We use qwen2.5:14b locally for development. The Planner/Checker
   judgments are therefore lower-quality than the original; this is expected and is
   why headline results will eventually be reproduced on a GPT-4o-class model. Any
   fidelity check against the paper's clean-completion / attack-block numbers must
   account for this model gap.

**Validation plan:** a fidelity check (our reimplementation's clean-completion rate
and attack-block rate vs. the paper's reported figures, within a stated tolerance)
will show whether these judgment calls materially distorted behaviour. If close,
that is evidence the calls are benign.