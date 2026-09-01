# BCSE497J – Project-I

## LaunderLens: Measuring Label Integrity in Taint-Tracking Defences for Multi-Agent LLM Systems

*(Times New Roman 16, Bold, Upper Case, Line spacing 1.5 — per template)*

**B.Tech. in Computer Science and Engineering (Specialization: Information Security)**
School of Computer Science and Engineering (SCOPE)

---

## ABSTRACT

Large Language Model (LLM) agents that call external tools — reading email, moving money, inviting workspace members — are now screened by taint-tracking security gateways such as AuthGraph and RTBAS, which label incoming data "trusted" or "untrusted" before letting an action execute. Every existing evaluation of these gateways asks one question only: *was the attack blocked?* This project shows that question is insufficient. A gateway can reach the *correct outcome* through *dishonest internal reasoning* — it blocks or allows an action for the wrong reason — and that same dishonest reasoning fails silently under a slightly different attack. We call this failure mode **label laundering**.

LaunderLens is a measurement apparatus, built end-to-end on the AgentDojo benchmark with local LLMs (Ollama-served `qwen2.5:14b`), that audits whether a security gateway's own trust labels are *honest* rather than merely whether its final decision was correct. Its core mechanism is a **Counterfactual Execution Oracle**: it takes a completed agent trace, surgically removes the suspected malicious payload, substitutes a length- and content-matched neutral filler, and re-executes the entire pipeline — gateway included. If the security-relevant action changes only when the real payload is present, the payload was causally influential; the gateway's label is then checked against this ground truth to compute a **Label Integrity Score (LIS)**.

Using this oracle, we reimplemented four published defences (AuthGraph, RTBAS, Fides, CaMeL) from their papers' own specifications and ran a matrix of nine crafted "laundering" attack variants across two AgentDojo domains (banking — financial fraud; Slack — unauthorized access grant). The results are stark and reproducible: **every case where the oracle confirmed the payload was causally influential produced a dishonest "trusted" label from AuthGraph (0/53 honest)**, because its Layer-3 verbatim-match shortcut cannot tell a legitimately-sourced value from an attacker's value planted inside the same already-compromised document. **RTBAS's stricter, no-fast-path policy check caught every one of the same cases honestly (24/24 honest across n=3–9 seeds)**. Oracle reliability itself was independently validated by blind human rating: 24/24 agreement, Cohen's κ = 1.000. This is a genuine, mechanism-linked, reproducible finding, not an artifact of one suite or one task.

**Keywords** — LLM Agent Security, Taint Tracking, Prompt Injection, Label Integrity, Counterfactual Reasoning, AI Security Gateways, AgentDojo.

---

## TABLE OF CONTENTS

| Sl.No | Contents | Page No. |
|---|---|---|
| | **Abstract** | i |
| 1. | **INTRODUCTION** | 1 |
| | 1.1 Background | 1 |
| | 1.2 Motivation | 1 |
| | 1.3 Scope of the Project | 1 |
| 2. | **PROJECT DESCRIPTION AND GOALS** | 2 |
| | 2.1 Literature Review | 2 |
| | 2.2 Research Gap | 2 |
| | 2.3 Objectives | 2 |
| | 2.4 Problem Statement | 2 |
| | 2.5 Project Plan | 2 |
| 3. | **TECHNICAL SPECIFICATION** | 3 |
| | 3.1 Requirements (Functional / Non-Functional) | 3 |
| | 3.2 Feasibility Study | 3 |
| | 3.3 System Specification (Hardware / Software) | 3 |
| 4. | **DESIGN APPROACH AND DETAILS** | 4 |
| | 4.1 System Architecture | 4 |
| | 4.2 Design (Data Flow / Use Case / Sequence Diagrams) | 4 |
| 5. | **REFERENCES** | 5 |

---

## 1. INTRODUCTION

### 1.1 Background

Modern LLM agents are not passive chatbots — they read files, call APIs, and execute real-world actions such as sending money or granting account access. This capability creates a direct attack surface: **prompt injection**, where an attacker plants instructions inside data the agent reads (a bill, a webpage, an email) hoping the agent will obey them as if they came from its legitimate user. The current generation of defences against this — provenance-tracking or "taint-tracking" security gateways such as **AuthGraph** and **RTBAS** — work by labelling every piece of information the agent sees as "trusted" (from the user) or "untrusted" (from an external document) and blocking actions whose arguments trace back to untrusted sources. Every published evaluation of these gateways, including the most recent adaptive-attack study (arXiv:2606.26479), measures success the same way: **Attack Success Rate (ASR)** — did the malicious action happen or not? This project's central claim is that ASR is an incomplete instrument: it cannot see *why* a gateway made its decision, only *what* the decision was.

### 1.2 Motivation

A security gateway can block an attack for the wrong reason. If its underlying trust-labelling logic is unsound, the *same* flawed logic will eventually pass a slightly different attack that ASR-based testing never happened to try. This is the **"right answer, wrong reason"** problem: an evaluation that only checks outcomes cannot distinguish a genuinely robust gateway from one that got lucky on the specific attacks it was tested against. Concretely, we hypothesized that a gateway's provenance-tracking mechanism could be tricked into **laundering** an attacker-controlled value — certifying it as "trusted" — if the attacker's payload sits inside the *same document* as a legitimate value the gateway is designed to trust (e.g., a forged IBAN appended to the same bill file that contains the real one). Standard ASR testing, run against the *whole* pipeline's final action, has no way to isolate and confirm this internal dishonesty even when it is present and even when the visible outcome happens to be "attack blocked."

### 1.3 Scope of the Project

This project designs, builds, and validates **LaunderLens**, a measurement apparatus that audits the *label honesty* of LLM security gateways, independent of and in addition to their attack-blocking rate. The scope, as locked for this submission, covers:

- A **Counterfactual Execution Oracle** that behaviorally determines ground-truth causal influence by re-executing a full agent pipeline with the suspected payload surgically replaced by a matched neutral filler.
- A **Label Integrity Score (LIS)**, computed at the final security-relevant action ("LIS-sink") and, at lower confidence, at intermediate reasoning hops ("LIS-all").
- Faithful reimplementations of **four published defences** — AuthGraph, RTBAS, Fides, CaMeL — built directly from their papers' specifications (no public reference code exists for AuthGraph or RTBAS), each with disclosed engineering approximations.
- **Nine crafted attack variants** across three attack classes (attribution forgery, label-join granularity, multi-hop re-emission) applied to two AgentDojo domains — banking (financial fraud) and Slack (unauthorized access) — using local models (`qwen2.5:14b`, `llama3.1:8b` via Ollama) for zero-cost, fully reproducible experimentation.
- Independent validation of the oracle's own reliability via blind human rating (Cohen's κ).

Explicitly **out of scope** for this submission (deferred to the post-review closure plan): a capable-model (GPT-4o-class) reproduction pass, a formal utility/over-blocking trade-off measurement, and full statistical confidence-interval reporting. These are documented next steps, not omissions.

---

## 2. PROJECT DESCRIPTION AND GOALS

### 2.1 Literature Review

The reimplementation and experimental design in this project are grounded directly in the following primary sources (representative subset; full list in References):

1. **AuthGraph** (UVA) — proposes a three-component reasoning-graph pipeline (Graph Builder, Planner, Checker) that labels nodes trusted/untrusted/inherited and checks parameter provenance before allowing a tool call. Its own paper acknowledges "same-observation pollution" as a known, unaddressed limitation — the exact surface this project exploits and measures.
2. **RTBAS** (CMU, arXiv:2502.08966) — a dependency-screener defence combining an LM-as-judge and an attention-saliency screener, joining labels of all relevant regions and masking irrelevant ones. Screens taint *per-action*, not transitively, which shapes which attack classes apply to it.
3. **Fides** (Microsoft, arXiv:2505.23643) — a two-lattice (integrity × confidentiality) information-flow-control planner with a join-and-policy-abort algorithm.
4. **CaMeL** (Google DeepMind, arXiv:2503.18813) — a capability model tracking provenance and allowed-readers per value, gating tool calls via an explicit policy function.
5. **"Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection"** (arXiv:2606.26479) — the closest prior evaluation; tests CaMeL, Fides, Progent, RTBAS, FORGE under adaptive attacks but measures **attack success only**, never internal label correctness, and does not cover AuthGraph.
6. **NeuroTaint / "Ghost in the Agent"** — uses counterfactual re-execution to detect whether *content* is dangerous. This project reuses the counterfactual mechanism but points it at a different target: the *defence's own verdict*, not the payload.
7. **MemLineage** (arXiv:2605.14421) — achieves "label integrity" via cryptographic tamper-*proofing* of memory across sessions. This project instead measures live, behavioral label *truthfulness* within a single-task pipeline — a different question, different mechanism, different setting.
8. **AgentDojo** benchmark (ETH Zurich) — supplies the agent pipeline, 97 user tasks, 629 injection cases across four tool-use domains, and a non-LLM formal success checker used as this project's ASR ground truth.

A fuller literature survey (up to the required 50-paper depth, including Choudhary et al. AISec 2025, PermissiveIFC, and adjacent IFC/agent-trust papers) is maintained as a living document in the project repository (`paper/differentiation.md`) and will be finalized for the Project-II report.

### 2.2 Research Gap

No existing published evaluation of LLM agent security gateways measures whether the gateway's *internal trust label* is honest, independent of the final blocked/allowed outcome. Outcome-only metrics (ASR) are structurally blind to a defence that reaches the right decision via unsound reasoning — meaning current evaluations cannot detect a whole class of "right answer, wrong reason" vulnerabilities that will resurface under the next slightly-different attack. This is the specific, previously unaddressed gap LaunderLens targets.

### 2.3 Objectives

- Design and implement a **Counterfactual Execution Oracle** capable of causally determining, for any completed agent trace, whether a suspected payload actually influenced the final security-relevant action.
- Define and compute a **Label Integrity Score (LIS)** that cross-references a defence's stated trust label against this oracle-derived ground truth, separately from Attack Success Rate.
- Reimplement at least two (stretch: four) published LLM security gateways faithfully enough to pass a stated fidelity check against their own papers' reported clean-behaviour numbers.
- Craft and execute attacks targeting each reimplemented gateway's specific labelling mechanism, and quantify how often each gateway launders an attacker-controlled value as "trusted."
- Validate the oracle's own measurement reliability via independent blind human agreement (Cohen's κ) on a representative case sample.
- Demonstrate the finding generalizes across at least two structurally different application domains (financial transaction vs. access-control), not one suite's tool shapes.

### 2.4 Problem Statement

**Given a deployed LLM agent protected by a taint-tracking security gateway, determine — independent of whether the gateway's final decision (block/allow) is "correct" by outcome — whether the gateway's internal trust labels are causally honest, and quantify how often, and under what specific mechanism, an attacker can force a dishonest "trusted" label onto attacker-controlled data.**

### 2.5 Project Plan

The project followed a phased implementation plan (see `plan/IMPLEMENTATION_PLAN.md`), executed and tracked against a running progress log (`PROGRESS.md`). As of this review (Review 2), the following phases are **complete and locked**:

| Phase | Deliverable | Status at Review 2 |
|---|---|---|
| 1 | AgentDojo + local-model harness, `Trace` data structure, `runner.py` | ✅ Complete |
| 2 | Counterfactual Execution Oracle, stability filter, LIS-sink/LIS-all scoring, ASR scoring | ✅ Complete |
| 3 | AuthGraph reimplementation, live fidelity check, LIS-with-defence cross-reference | ✅ Complete |
| 4 | Two crafted laundering attacks (attribution forgery, label-join) built and run against AuthGraph vs RTBAS | ✅ Complete — GO/NO-GO passed |
| 5 | Expansion: RTBAS, Fides, CaMeL reimplemented; nine attack variants; three-domain generalization (banking, Slack; workspace deprioritized as a documented model-capability limit); oracle κ validated at 1.000 across 24 blind-rated cases | ✅ Complete |
| 6 | Statistical rigor, utility/over-blocking trade-off, capable-model pass, write-up | ⏸ **Deliberately paused for Review 2** — resumes per the post-review Closure Plan |

A Gantt-style phase timeline is maintained in the repository and will be included as **Fig. 1** in the final formatted submission.

---

## 3. TECHNICAL SPECIFICATION

### 3.1 Requirements

#### 3.1.1 Functional

- The system shall drive a complete AgentDojo agent task (banking, Slack) end-to-end through a local LLM and record a structured, immutable JSON trace of every hop and tool call.
- The system shall optionally inject a crafted attack payload into a specified injection vector and record the resulting (poisoned) trace alongside a matched clean baseline.
- The system shall programmatically excise an injected payload from a poisoned trace and substitute a policy-compliant neutral filler, then re-execute the full pipeline including the security defence under test.
- The system shall compare the security-relevant final action (and its deterministic arguments — recipient, amount, IBAN, email) across the real and filler-substituted runs to determine causal influence ("ground truth").
- The system shall apply a **stability filter**: across n ≥ 3 distinct neutral fillers, if the security-relevant action fluctuates with no attack present, the case is marked unusable and excluded from scoring.
- The system shall replay each completed trace through a pluggable `Defence` interface (AuthGraph, RTBAS, Fides, CaMeL) to obtain a per-hop trust label and screener decision.
- The system shall compute, from logged traces only (never hand-entered), Attack Success Rate (ASR), Label Integrity Score (LIS-sink, LIS-all), and Screener Evasion Rate (SER), per attack × per defence.
- The system shall support batch experiment execution (`run_experiment.py`, `run_phase4.py`, `run_matrix.py`) across an attack × variant × defence × seed matrix, with dry-run validation before any model call.

#### 3.1.2 Non-Functional

- **Reproducibility:** every run is pinned to a fixed seed, temperature 0, and the exact git commit hash of the codebase; results must be regenerable from logs by script, never hand-typed into a report.
- **Determinism of measurement:** the oracle's filler policy is locked and frozen (real/benign text, ±15% token length of the original payload, no imperatives/second-person/account references) *before* any results are examined, to prevent post-hoc rationalization.
- **Auditability:** every engineering approximation made while reimplementing a published defence (`APPROX` tags) is disclosed inline in code and cross-referenced in `paper/differentiation.md`.
- **Local-first operation:** the entire pipeline runs against locally-hosted models (Ollama: `qwen2.5:14b`, `llama3.1:8b`) with zero external API cost, enabling unlimited experiment iteration during development.
- **Portability:** the codebase runs on both Windows and Unix shells (ASCII-only terminal output; verified after a Windows `cp1252` encoding defect was found and fixed).
- **Data integrity:** logs are never hand-edited; a wrong result is fixed by fixing the code and re-running, not by editing the JSON.

### 3.2 Feasibility Study

#### 3.2.1 Technical Feasibility
The project builds entirely on **AgentDojo**, a public, actively maintained benchmark that already supplies the agent pipeline, tool suites, 97 user tasks, and a formal (non-LLM) success checker — removing the need to build an agent framework from scratch. Neither AuthGraph nor RTBAS has released reference code, but both papers publish sufficient specification (AuthGraph's full system prompts in Appendix A; RTBAS's exact per-action screening algorithm) to support a faithful reimplementation, which was confirmed feasible and completed within the planned timeframe. Local model hosting via Ollama removes any dependency on paid API access for development-phase results.

#### 3.2.2 Economic Feasibility
All development-phase experimentation runs on locally-hosted open-weight models at zero marginal cost. The only anticipated future cost is an optional capable-model (GPT-4o-class) reproduction pass, explicitly gated on budget availability in the post-review closure plan, and is not required for this submission's results.

#### 3.2.3 Social Feasibility
The project follows a **responsible-disclosure** practice: authors of AuthGraph (UVA) and RTBAS (CMU), and Fides (Microsoft) and CaMeL (Google DeepMind) where applicable, will be notified of the specific laundering mechanism found, with dated records, before or alongside any public release — standard practice for security research of this kind, and scheduled explicitly in the post-review plan.

### 3.3 System Specification

#### 3.3.1 Hardware Specification
- Standard development workstation (Windows 11), no GPU strictly required for the 8B/14B local models used (CPU-served via Ollama, acceptable latency for research iteration).
- Minimum 16 GB RAM recommended for concurrent 14B-parameter local inference.

#### 3.3.2 Software Specification
- **Operating System:** Windows 11 (development), cross-platform compatible (PowerShell / POSIX shell).
- **Programming Language:** Python 3.12.
- **Agent Framework:** AgentDojo (`agentdojo==0.1.35`).
- **Local Model Serving:** Ollama, models `qwen2.5:14b` and `llama3.1:8b`.
- **Core Libraries:** standard library `json`, `dataclasses`, `uuid`; no external ML training dependencies (defences are prompt/logic-based, not trained classifiers).
- **Version Control:** Git, with every experimental log tagged to its exact commit hash for reproducibility.

---

## 4. DESIGN APPROACH AND DETAILS

### 4.1 System Architecture

LaunderLens is organized around one central invariant: **everything flows through a single immutable `Trace` object, and every run writes one JSON log file that is never hand-edited.** The architecture has five layers:

1. **Pipeline layer** (`pipeline/`) — `runner.py` drives one AgentDojo task under a chosen (attack, defence, model, seed) configuration and emits a `Trace`; `trace.py` defines the trace schema (hops, agent role, defence label, screener decision, final action, all executed actions).
2. **Attack layer** (`attacks/`) — pluggable payload generators implementing a shared interface: `(benign task, injection slot) → crafted payload`. Implemented: `attribution_forgery.py`, `label_join.py`, `multi_hop_reemission.py`, `workspace_attacks.py`/`slack_invite_redirect` variants, plus a broader structural-attack family (`structural_attacks.py`, `rtbas_attacks.py`).
3. **Defence layer** (`defenses/`) — a common `Defence` interface with four reimplementations: `authgraph.py`, `rtbas.py`, `fides.py`, `camel.py`, each replaying its labelling/policy-check logic post-hoc over a completed trace and each documenting its `APPROX` engineering judgment calls inline.
4. **Metrics/Oracle layer** (`metrics/`) — `counterfactual.py` (the oracle engine: payload excision, filler substitution, re-execution, stability filter), `actions_differ.py` (the pre-registered rule for "did the security-relevant action change"), `asr_score.py`, `lis_score.py`, `iban_match.py` (suite-generic attacker-value matching).
5. **Experiments/Analysis layer** (`experiments/`, `analysis/`) — batch drivers (`run_experiment.py`, `run_phase4.py`, `run_matrix.py`) that sweep the attack × variant × defence × seed matrix, and `rescore_phase4.py` / `kappa_rate.py` that re-derive all headline numbers from saved JSON logs with zero new model calls, ensuring every number is regenerable and auditable.

*Fig. 2 — System Architecture: attacker payload → agent pipeline (AgentDojo + local LLM) → security defence layer (label/screener decision) → Counterfactual Oracle (payload excision + re-execution) → divergence comparison → LIS/ASR scoring → immutable JSON log.* (Diagram source: `architecture_diagram.py` / `generate_diagrams.py`, rendered assets in `diagrams/`.)

### 4.2 Design

#### 4.2.1 Data Flow Diagram *(Mandatory)*
Traces the flow: **benign task + attack payload → AgentDojo environment → agent (local LLM) tool calls → hop-by-hop trace recording → defence replay (label + screener decision) → counterfactual re-execution (3× neutral fillers) → action-divergence comparison → LIS/ASR/SER computation → JSON result file → analysis/rescoring scripts → result tables.** (Full diagram exported from `generate_diagrams.py`, included as a figure in the formatted submission.)

#### 4.2.2 Use Case Diagram *(Mandatory)*
Primary actors: **Researcher** (configures and runs an experiment matrix; inspects results), **Attacker (modeled)** (payload injected via AgentDojo's injection-vector mechanism), **Security Gateway under test** (AuthGraph / RTBAS / Fides / CaMeL, invoked as a replay module). Use cases: *Run clean baseline*, *Run poisoned trace*, *Run counterfactual filler set*, *Apply defence to trace*, *Compute LIS/ASR/SER*, *Rescore existing results*, *Validate oracle via blind human rating*.

#### 4.2.3 Class Diagram *(Optional — included)*
Core classes: `Trace`, `Hop`, `PipelineConfig`, `Attack` (base + concrete subclasses per attack variant), `Defence` (base + `AuthGraph`, `RTBAS`, `Fides`, `CaMeL`), `OracleVerdict`, `CounterfactualResult`. Relationships: `runner.py` composes a `PipelineConfig` and an `Attack` to produce a `Trace`; a `Defence` consumes a `Trace` and annotates its `Hop`s; the Oracle consumes a matched (poisoned, filler×3) set of `Trace`s and emits an `OracleVerdict`.

#### 4.2.4 Sequence Diagram *(Optional — included)*
Sequence for one experimental cell: Researcher → `run_phase4.py` → `runner.py` (clean run) → `runner.py` (poisoned run, attack injected) → `apply_defense.py` (defence replay on poisoned trace) → `counterfactual.py` (3× filler re-runs) → `actions_differ.py` (divergence check per filler) → stability filter → `lis_score.py` (cross-reference defence label vs. oracle verdict) → result JSON written → `rescore_phase4.py` (independent re-derivation, sanity check).

*(All four diagrams are generated/maintained via `architecture_diagram.py` and `generate_diagrams.py`, with rendered output in `diagrams/`, and will be inserted as numbered figures in the final Word-formatted submission per the template's font/spacing rules.)*

---

## 5. REFERENCES

**Journals / Preprints (IEEE format):**

1. R. Zhong et al., "RTBAS: Defending LLM Agents Against Prompt Injection via Runtime Taint-Based Access Control," arXiv:2502.08966, 2025.
2. J. Wang, Y. Li, and R. Tian, "AuthGraph: Reasoning-Graph-Based Provenance Tracking for LLM Agent Security," University of Virginia, 2026.
3. M. Costa et al., "Fides: Enforcing Information Flow Control for LLM Agents via Integrity and Confidentiality Lattices," arXiv:2505.23643, Microsoft, 2025.
4. E. Debenedetti et al., "CaMeL: A Capability-Based Defense Against Prompt Injection in LLM Agents," arXiv:2503.18813, Google DeepMind, 2025.
5. S. Narisetty et al., "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents," arXiv:2606.26479, 2026.
6. "MemLineage: Cryptographic Label Integrity for Agent Memory Systems," arXiv:2605.14421, 2026.
7. "From Agent Traces to Trust: A Survey of Behavioral Security Evaluation for LLM Agents," arXiv:2606.04990, 2026.
8. "Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents," arXiv:2604.04035, 2026.
9. "FAVA: A Faithful Reimplementation and Audit of Graph-Based LLM Agent Defenses," arXiv:2607.27267, 2026.
10. A. Choudhary et al., "How Not to Detect Prompt Injections with an LLM," AISec Workshop, ACM CCS, 2025.
11. ETH Zurich SPY Lab, "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents," `github.com/ethz-spylab/agentdojo`, 2025.

**Weblinks:**

12. Ollama local model runtime — `https://ollama.com`.
13. AgentDojo project repository and documentation — `https://github.com/ethz-spylab/agentdojo`.

*(Full literature review will be expanded to the required depth for the Project-II final report, per `paper/differentiation.md`.)*
