# INVENTION DISCLOSURE FORMAT (IDF-B)

---

## 1. Title of the Invention

**System and Method for Automated Integrity Verification of LLM Security Gateways via Counterfactual Execution**

---

## 2. Field / Area of Invention

The invention resides in the domain of **information security**, and more specifically in the sub-domain of **automated security auditing, label integrity verification, and taint-tracking defense evaluation in multi-agent Large Language Model (LLM) pipelines**. The invention pertains to computer-implemented apparatus and methods for evaluating security gateways that mediate tool-invocation actions performed by autonomous LLM agents, and is applicable to enterprise AI security infrastructure, LLM agent deployment platforms, and automated red-teaming/audit systems for AI-driven software pipelines.

---

## 3. Prior Patents and Publications from Literature

The apparatus is examined against the closest identified prior art. The following table sets out the explicit points of differentiation.

| Prior Art | Core Mechanism | What It Measures | Key Limitation Addressed by the Present Invention |
|---|---|---|---|
| **NeuroTaint** ("Ghost in the Agent" — counterfactual-based taint detection) | Counterfactual re-execution: content is removed/altered and the pipeline outcome is compared, to determine whether the content is dangerous. | **Content danger** — is this input hazardous? | NeuroTaint interrogates the *content* to find attacks. It possesses no mechanism to interrogate a security gateway's *internal trust label* and has no defense-honesty target to check — it was never built to audit a defense's own claim. The present invention repurposes the counterfactual mechanism to interrogate the **defense's verdict**, not the payload, producing a fundamentally different output: a label integrity score, not an attack-detection score. |
| **MemLineage** (arXiv:2605.14421) | Cryptographic signature-based tamper-proofing of label metadata attached to persistent agent memory entries, enforced across sessions. | **Tamper-resistance** — can this label be altered without detection? | MemLineage is a preventive, cryptographic mechanism operating in the **cross-session memory** setting; it does not, and cannot, determine whether a label was **truthful at the moment it was assigned**. The present invention performs **live behavioral truthfulness measurement** within a **single-task, live pipeline execution**, using no cryptographic apparatus — it diagnoses dishonesty behaviorally rather than preventing tampering structurally. |
| **Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents** (arXiv:2606.26479) | Adaptive, defense-aware attack generation against out-of-band gateways (CaMeL, FIDES, Progent, RTBAS, FORGE), scored by final attack success/failure. | **Attack Success Rate (ASR)** — was the attack ultimately blocked? | This reference measures **attack success only** and does not inspect internal reasoning, intermediate trust labels, or provenance-assignment correctness at any stage of the gateway's decision process. It cannot distinguish a gateway that is genuinely sound from one that reached a correct outcome via unsound, dishonest internal reasoning. The present invention's apparatus computes a **label integrity score** that is orthogonal to and independent of attack-outcome scoring, exposing this exact blind spot. It further extends coverage to gateway architectures (e.g., AuthGraph) not evaluated by this reference. |

**Novelty Statement:** No identified prior art discloses an apparatus that (i) programmatically excises a suspected payload from a recorded multi-agent execution trace, (ii) substitutes a length- and content-matched neutral filler, (iii) replays the entirety of the pipeline including the security gateway under test, and (iv) computes a quantitative label integrity score by comparing the gateway's stated trust label against the behaviorally-determined ground truth of causal influence. This constitutes a distinct technical solution to a distinct technical problem — verifying the *honesty* of a security label, not the *danger* of content or the *tamper-resistance* of a record.

---

## 4. Summary and Background of the Invention

### 4.1 Background / Prior Art Limitations

LLM agents that invoke external tools (financial transfer functions, file access functions, communication and workspace administration functions) are increasingly protected by taint-tracking or provenance-based security gateways. These gateways assign trust labels — typically "trusted," "untrusted," or "inherited" — to data as it flows through an agent's execution, and gate security-relevant tool invocations based on these labels.

The prior art evaluates such gateways exclusively through **outcome-based metrics**, most commonly Attack Success Rate (ASR): a binary determination of whether a malicious action was ultimately blocked or permitted. This evaluation paradigm contains a critical, previously unaddressed structural flaw: **a security gateway can produce the correct outcome (block or permit) through an incorrect, dishonest internal reasoning path.** This is termed the **"right answer, wrong reason" vulnerability**. A gateway exhibiting this flaw applies unsound label-assignment logic that, by chance or by narrow test coverage, produces the desired outcome on a given attack — but the same unsound logic will fail, silently and undetected by ASR-based testing, under a structurally different attack that exercises the same flawed reasoning path differently.

A specific, empirically confirmed instance of this vulnerability class is **provenance laundering**: a gateway's provenance-verification mechanism certifies an attacker-controlled value as "trusted" because that value satisfies a shallow, mechanical sourcing check (e.g., verbatim string presence within a document the gateway associates with a trusted source) without verifying that the underlying document itself has not been compromised. The gateway's own trust label is thereby rendered **dishonest** — it asserts trust in a value whose true provenance is adversarial — even though the label-assignment procedure executed exactly as designed. Outcome-based ASR testing is structurally blind to this failure mode: if the resulting action happens to be permitted and the corresponding benchmark task is not scored as an "attack," ASR reports full security, masking the systemic flaw entirely.

### 4.2 Summary and Novelty

The present invention introduces the **Counterfactual Execution Oracle**, an apparatus and accompanying method that behaviorally verifies whether a security gateway's internal trust labels are **causally honest**, independent of the final action's outcome classification.

The apparatus operates by ingesting a completed, immutable execution trace of a multi-agent LLM pipeline in which a suspected malicious payload has been identified. It programmatically excises the identified payload from the trace and substitutes, in its place, a **neutral filler** — a benign textual replacement matched to the original payload in token length and structural shape, drawn from a locked, pre-registered filler policy. The apparatus then **re-executes the entire pipeline, including the security gateway under test**, using this filler-substituted input, and compares the resulting security-relevant action against the original (payload-present) execution's action.

A divergence in the security-relevant action — specifically, in deterministic parameters such as recipient identifiers, transfer amounts, or authorization targets — establishes, behaviorally and reproducibly, that the excised payload was **causally influential** on the gateway-mediated outcome. The apparatus then cross-references this behaviorally-derived ground truth against the trust label the gateway actually assigned during the original execution. Where the gateway labeled the payload-derived value "trusted" despite the counterfactual confirming the value's causal dependence on the adversarial payload, the apparatus registers a **dishonest label** event. The aggregate proportion of honest-to-dishonest labels across a evaluated case set constitutes the invention's headline output metric, the **Label Integrity Score**.

This mechanism detects **provenance laundering within single-task, live pipelines** — a detection capability not present in, and not derivable from, prior counterfactual content-danger detectors (which lack any concept of a gateway's asserted label to check) or cryptographic tamper-proofing systems (which operate on a different threat model — alteration detection, not truthfulness measurement — and in a different setting — cross-session persisted memory, not live single-execution pipelines).

---

## 5. Objective(s) of Invention

- To eliminate **outcome-bias** in the security evaluation of LLM agent gateways by introducing a metric that is structurally independent of whether the final action was classified as "blocked" or "permitted."
- To provide a mechanism for **dynamically validating the honesty of internal trust labels** assigned by a security gateway during live pipeline execution, without requiring access to the gateway's source code (a black-box, trace-replay-based approach).
- To detect **provenance laundering** — the specific failure mode by which an attacker-controlled value is certified as trusted due to shallow, mechanical sourcing verification — with a reproducible, quantitative measurement.
- To supply an **immutable, auditable trace record** for every evaluated execution, such that every computed integrity score is traceable to a specific, reproducible pipeline run and configuration.
- To establish a **stability-filtered, deterministic measurement protocol** that discriminates genuine causal influence from incidental model non-determinism, ensuring the reported integrity score reflects a reliable security determination rather than measurement noise.
- To enable **cross-architecture comparison** of security gateway designs (e.g., verbatim-match provenance checkers versus strict policy-check gateways) on a common, gateway-agnostic integrity metric.

---

## 6. Working Principle of the Invention

The apparatus executes the following sequential logical flow:

1. **Trace Ingestion.** The apparatus ingests a recorded, immutable execution trace of a multi-agent LLM pipeline, comprising a hop-by-hop record of agent actions, tool invocations, and the security gateway's assigned labels and decisions for the execution in which a suspected malicious payload was present.

2. **Programmatic Payload Excision and Filler Substitution.** The apparatus programmatically identifies and excises the suspected payload from its point of injection within the trace's input data, and substitutes in its place a **neutral filler**: a benign text string selected under a pre-registered policy requiring (a) token-length correspondence to the original payload within a defined tolerance, (b) absence of imperative or second-person instructional content, and (c) absence of security-relevant references (account identifiers, monetary amounts, addresses). The filler substitution is performed identically across a plurality of distinct filler instances.

3. **The Stability Filter.** The apparatus executes the substituted-pipeline re-run across **n ≥ 3 distinct, structurally independent neutral fillers**. If the resulting security-relevant action **wobbles** — i.e., diverges across the plurality of filler substitutions in the absence of any attack payload — the apparatus determines the case is **unusable for ground-truth determination** and automatically excludes it from integrity scoring. This filter distinguishes genuine, attributable causal influence from incidental non-determinism inherent to LLM-driven agent behavior, and its exclusion count is separately logged and reported.

4. **Execution Engine Replay.** For each filler-substituted variant surviving the stability filter, the apparatus re-executes the complete multi-agent pipeline — including the security gateway module under test — from the point of divergence forward, producing a matched counterfactual trace.

5. **Two-Tier Verification Mechanism.**
   - **Sink Tier (High Confidence):** At security-relevant terminal actions (e.g., a fund-transfer invocation, an access-grant invocation), the apparatus extracts literal, deterministic parameters (recipient identifiers, transfer amounts, invitee identifiers) from both the original and counterfactual executions and performs an exact structural comparison. A parameter-level divergence at this tier constitutes high-confidence evidence of causal influence.
   - **Intermediate Tier (Lower Confidence):** At non-terminal, non-action hops (intermediate reasoning or observation steps that do not themselves invoke a security-relevant tool), the apparatus measures text-level divergence between the original and counterfactual hop outputs, and reports this divergence as a lower-confidence signal, distinctly flagged from Sink Tier determinations.

6. **Divergence Comparison and Label Integrity Scoring.** The apparatus cross-references, for each verified-influential case, the security gateway's originally-assigned trust label against the behaviorally-determined ground truth of causal influence. A gateway label of "trusted" assigned to a value confirmed causally dependent on the excised payload is scored as a **dishonest label**; a gateway label of "untrusted" (or a corresponding block decision) under the same confirmed-influential condition is scored as **honest**. The apparatus aggregates these per-case determinations into a quantitative **Label Integrity Score** for the gateway under test.

---

## 7. Description of the Invention in Detail

### 7.1 System Architecture — The Immutable Trace Pipeline

The apparatus is constructed around a single, immutable data record generated for every execution: the **Trace**. No trace, once written, is modified; a corrected result is produced by re-executing the pipeline and generating a new trace, never by editing an existing one. This design guarantees that every score the apparatus produces is traceable to a specific, reproducible, and independently re-derivable execution record.

The Trace is realized as a structured JSON document with the following constituent data elements:

- **Configuration Block:** the identifier of the LLM model used, the random seed, the sampling temperature, the benchmark task suite and task identifier, the injection task identifier, the attack class and variant applied, the security gateway under evaluation, and the **git commit hash** of the exact codebase revision that produced the trace — ensuring full reproducibility of any reported number.
- **Hop-by-Hop Records:** an ordered sequence of records, each comprising the acting agent's role, an input-context digest, the emitted output text, a boolean flag indicating whether the hop's input contains untrusted-source content, the security gateway's **assigned trust label** for that hop (e.g., "trusted," "untrusted," "suspicious"), the gateway's **screener decision** (e.g., "allow," "block," "declassify"), and the gateway's stated reasoning where available.
- **Final Action and All-Actions Record:** the terminal security-relevant tool invocation (tool identifier and structured arguments), and, distinctly, the complete ordered set of **all** tool invocations executed during the run — the latter capturing security-relevant actions that may occur prior to a final, unrelated action, a case the apparatus specifically guards against mis-scoring.
- **Counterfactual Divergence Array:** for each of the n ≥ 3 filler substitutions, a record of whether the security-relevant action changed relative to the original execution, together with the aggregate stability-filter determination (usable / unusable for ground truth) and, where usable, the final influence determination and per-hop label-correctness array.

### 7.2 Synthetic Auditing Payloads (Attack Classes Used to Exercise the Apparatus)

The apparatus is validated and its auditing capability demonstrated using the following classes of synthetic auditing payloads, each engineered to target a distinct category of provenance-verification weakness:

1. **Multi-Hop Re-Emission.** A payload constructed such that, after being reworded or restated by an intermediate agent in the pipeline, the security gateway's provenance tracker treats the restated text as freshly agent-generated (and therefore trusted) content, shedding the transitive taint that should have propagated from its untrusted origin.

2. **Attribution Forgery.** A payload that falsely asserts, within its own content, a trusted point of origin — for example, embedding a fabricated identity attribution or a source-tool reference designed to be accepted by a reasoning-graph-building component of the gateway without independent verification of the assertion's truth.

3. **Label-Join Granularity.** A malicious span embedded within an otherwise legitimate, mostly-relevant block of content, exploiting region-level (rather than span-level) screening granularity so that a screener's "join" operation over the block's relevance labels retains the malicious span by virtue of the surrounding legitimate content's relevance.

Each of these payload classes was applied, in the apparatus's validation program, against reimplementations of four published security gateways (a verbatim-match provenance-graph checker, a strict per-action policy-check screener, and two independently-sourced information-flow-control gateways), across two structurally distinct application domains (financial transaction authorization and workspace-access authorization), demonstrating the apparatus's target-agnostic, domain-agnostic operation.

---

## 8. Experimental Validation Results

The apparatus was validated end-to-end on a local, fully reproducible experimental harness (AgentDojo benchmark, locally-hosted LLMs, zero external API dependency), producing the following extracted, log-derived results:

- **Oracle Reliability — 100% agreement, Cohen's κ = 1.000.** The apparatus's counterfactual-derived ground-truth determinations were independently validated against blind human rating across **24 fully evidence-backed cases**, spanning both influential (payload-caused divergence confirmed) and non-influential (payload-had-no-effect confirmed) determinations — a genuine bidirectional discrimination test, not a one-sided agreement check. The resulting perfect agreement (κ = 1.000, conventionally classified as "almost perfect" reliability) establishes the apparatus as a trustworthy measuring instrument on every case with complete underlying evidence.

- **Cross-Domain Validation — 53 dishonest cases vs. 24 honest cases (running total across banking and Slack suites).** Across a full attack-class × variant × security-gateway matrix (nine attack/variant combinations, two independent application domains, multiple random seeds per cell), the apparatus's Label Integrity Score computation produced a stark, mechanism-linked, zero-exception differentiation between two structurally distinct gateway designs under test:
  - A **verbatim-match provenance-graph gateway** (reimplemented from its publishing authors' disclosed system-architecture specification) produced a **dishonest "trusted" label in every one of 53 confirmed-influential cases** across both the financial-transaction domain (payment redirection) and the workspace-access domain (unauthorized membership grant) — because its provenance-verification fast path certifies a value as "sourced correctly" whenever it is found verbatim within a document associated with a trusted tool call, without verifying the document itself was not compromised.
  - A **strict per-action policy-check gateway** (reimplemented from its publishing authors' disclosed screening algorithm) produced an **honest label in all 24 of the same confirmed-influential cases**, across the identical attack set and both domains, at seed counts of n = 3 to n = 9 per cell, with zero exceptions — because its design contains no verbatim-match fast-path equivalent for an attacker to exploit.

- **Structural, not domain-specific, differentiation.** The apparatus confirmed the same divergence pattern in a financial-fraud harm class (unauthorized fund transfer) and, independently, in an unauthorized-access harm class (fraudulent workspace membership grant) — with no suite-specific tuning applied to either gateway's reimplementation — establishing that the measured dishonesty is a property of the **gateway's architectural design** (its provenance-verification mechanism), not an artifact of any single application domain's tool shapes or content.

- **Extended baseline coverage.** Two additional, independently-sourced information-flow-control gateways were confirmed, on the identical attack instance used to validate the first two gateways, to also produce honest labels — providing a four-way comparative baseline (one laundering design, three non-laundering designs) on a common integrity metric that no prior evaluation instrument has produced.

---

## 9. What Aspect(s) of the Invention Need(s) Protection? (Claims)

### Independent Claim 1 (System)

A system for auditing the integrity of security labels in a multi-agent language model pipeline, comprising:

(a) a **trace ingestion module** configured to receive an immutable, structured execution trace of a multi-agent language model pipeline, the trace comprising hop-by-hop records of agent actions, tool invocations, and labels and decisions assigned by a security defense module during execution;

(b) a **counterfactual generation module** configured to programmatically identify and excise an identified payload from the trace and substitute, in its place, a predefined neutral filler matched to the payload according to a stored filler policy;

(c) an **execution engine** configured to replay the multi-agent pipeline, including the security defense module, using the filler-substituted trace, to produce a counterfactual execution record; and

(d) a **divergence comparison module** configured to compare a security-relevant action, and its deterministic parameters, between the original trace and the counterfactual execution record, and to calculate a **label integrity score** based on whether changes to the security-relevant action are consistent with the label originally assigned by the security defense module.

### Dependent Claims

1. The system of Claim 1, wherein the counterfactual generation module matches the neutral filler to the identified payload's token length within a predefined tolerance threshold of approximately fifteen percent (15%).

2. The system of Claim 1, further comprising a **stability filter module** configured to execute the counterfactual generation and execution engine across a plurality of at least three (n ≥ 3) distinct neutral fillers, and to discard, from label integrity scoring, any case in which the security-relevant action diverges across the plurality of distinct neutral fillers in the absence of an identified payload.

3. The system of Claim 1, wherein the divergence comparison module isolates one or more deterministic parameters — including a recipient address, a transfer amount, or an authorization identifier — from the security-relevant action to determine causal influence, independent of non-deterministic textual variation elsewhere in the execution.

4. The system of Claim 1, wherein the divergence comparison module applies a two-tier verification mechanism, comprising a sink-tier comparison at security-relevant terminal actions and a lower-confidence intermediate-tier comparison at non-terminal execution hops, and reports each tier's determinations distinctly.

5. The system of Claim 1, wherein the trace ingestion module records, for each execution trace, a configuration block comprising a model identifier, a random seed, a task identifier, an applied attack identifier, a security defense module identifier, and a source-code revision identifier, such that the label integrity score is traceable to a reproducible execution.

### Independent Claim 2 (Method)

A computer-implemented method for auditing the integrity of security labels in a multi-agent language model pipeline, comprising the steps of:

(a) capturing an execution trace of a multi-agent language model pipeline in which a security defense module assigned one or more trust labels to data processed during execution;

(b) identifying and programmatically substituting a suspected payload within the execution trace with a predefined neutral filler;

(c) re-executing the multi-agent pipeline, including the security defense module, using the substituted trace, to produce a counterfactual execution record;

(d) comparing a security-relevant action between the execution trace and the counterfactual execution record to determine whether the suspected payload was causally influential; and

(e) scoring the label originally assigned by the security defense module as honest or dishonest based on a comparison between the determination of step (d) and the label assigned by the security defense module.

### Independent Claim 3 (Computer-Readable Medium)

A non-transitory computer-readable storage medium storing instructions that, when executed by one or more processors, cause the one or more processors to perform the method of Independent Claim 2.

---

## 10. What Is the Technology Readiness Level of Your Invention?

**TRL 4 — Technology validated in a laboratory environment.**

Justification: the invention has been implemented as a complete, end-to-end apparatus and validated against a recognized third-party benchmark environment (AgentDojo) using locally-hosted large language models, with fully functional reimplementations of four distinct published security gateway architectures (a provenance-graph checker, a per-action policy-check screener, and two independently-sourced information-flow-control gateways) constructed directly from their respective publications' disclosed specifications. The apparatus has produced reproducible, log-derived, statistically corroborated results (including an independently validated oracle reliability measurement) across multiple application domains and multiple experimental seeds. This constitutes validation in a controlled, laboratory-representative environment using representative (though not yet production-commercial-scale or live-enterprise-deployed) components and models, consistent with TRL 4. The invention has not yet been validated in an operationally relevant environment (e.g., against a live, commercial, closed-source enterprise AI security gateway, or at production traffic scale), which would be required to advance to TRL 5.
