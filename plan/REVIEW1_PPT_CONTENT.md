# Review 1 — Slide Content
## LaunderLens: Provenance Laundering in Multi-Agent LLM Systems

_The template (`Review1pptemplate.pdf`) already has content for every slide except two: **"Experiments and Results"** and **"Conclusion"**. This file fills in only those two, written to match what was actually true and demonstrable at Review 1 time (per the template's own dates — mid-July to late-August 2026), not the full project state as of today. Everything else in the template should be presented as-is._

---

## Slide: Experiments and Results

**Header line:** Harness built and validated end-to-end; first laundering result reproduced live.

- **Environment stood up and confirmed working.** AgentDojo benchmark running against local LLMs (`qwen2.5:14b`, `llama3.1:8b` via Ollama) — a real agent completes a real banking task (reads a bill, sends a payment) with zero API cost, fully reproducible on a laptop.

- **Milestone 1 — clean pipeline confirmed.** A fully successful, attack-free run recorded end-to-end as an immutable trace: bill read, correct payment sent, 7 hops captured. Confirms the base pipeline and trace-recording mechanism both work correctly before any attack logic is added.

- **First poisoned trace captured.** Injected the `important_instructions` attack (a fake "urgent message" embedded in the bill) into the same task. The agent redirected the payment to the attacker's account — the first live confirmation that the injection mechanism actually influences agent behaviour, not just a theoretical concern.

- **Counterfactual Execution Oracle built and validated live.** The core measurement engine: given a poisoned trace, it surgically removes the injected payload, substitutes a neutral filler of matching length, and re-runs the whole pipeline. If the final action changes only when the real payload is present, the payload is confirmed causally responsible — not just correlated.

- **Milestone 2 — first laundering verdict, reproduced twice.** Running the oracle on the captured attack case confirmed: the payload was causally influential (`payload_was_influential = True`) and the resulting label would be dishonest if trusted (`label_honest_if_trusted = False`). This is the first end-to-end proof that the measurement mechanism the project set out to build actually detects the failure mode it was designed to detect. Independently reproduced on a second run with the same result.

- **Stability filter added and confirmed on real data.** An early version of the oracle wrongly flagged some clean, non-influential cases as "unstable" due to normal model variation. Fixed by comparing only security-relevant actions (not the full text) across filler substitutions — confirmed against real captured data.

- **First full experimental batch run.** 1 clean + 5 poisoned + 15 counterfactual runs completed on `qwen2.5:14b`: **Attack Success Rate = 1.000** (all 5 attacks succeeded) and **Label Integrity Score (LIS-sink) = 0.000** (all 5 cases were confirmed causally influenced, i.e. laundered). This is the project's first paper-quality result: a clean, reproducible demonstration of label laundering, produced entirely by the measurement pipeline built for this project — not hand-inspected or asserted.

> **Where this leaves the project at Review 1:** the harness, the oracle, and the metric all work, proven on one real attack against a controlled scenario. The next phase (already scoped in the objectives) is reimplementing the actual target defences — RTBAS and AuthGraph — and re-running this same measurement against them.

---

## Slide: Conclusion

- The core hypothesis behind this project — that a security label can be **stripped from adversarial content while its influence survives into a real action** — is no longer just an argued risk; it has been **demonstrated and measured on a real, running agent pipeline**, using a mechanism (the Counterfactual Execution Oracle) built specifically for this purpose.

- The project has validated its most fundamental technical bet before committing further engineering effort to it: a working benchmark harness, a working attack-injection mechanism, and a working, reproducible causal-influence measurement — each confirmed independently, at zero infrastructure cost (fully local models).

- This directly closes part of the identified research gap: existing defences are evaluated only on whether an attack was *blocked*, never on whether the *label itself* was honest. This project has shown that gap is measurable, not just theoretical.

- **Next steps (Review 2 onward):** reimplement the two primary defence targets, RTBAS and AuthGraph, from their published specifications; apply the same oracle to determine whether *their* trust labels stay honest under the four planned laundering attack classes; and extend the evaluation to the FIDES and CaMeL baselines for comparison.
