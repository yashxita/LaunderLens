# LaunderLens: Patent Drafting Guide & Strategy

This document outlines the strategic narrative, required tone, and technical components necessary to successfully draft a patent application for the LaunderLens system. 

## 1. Tone and Narrative Strategy

### The Tone
The tone of the patent application must be **authoritative, objective, and highly mechanical**. Avoid academic hedging (e.g., "we explore," "we believe") and instead use definitive legal-technical language (e.g., "The system comprises," "The apparatus executes," "The method determines"). Frame LaunderLens not just as an evaluation metric, but as a **concrete, deployable auditing apparatus** for enterprise AI security gateways. 

### The Narrative (The "Problem-Solution" Arc)
Patents require a clearly defined problem in the "prior art" and a novel technical solution.
*   **The Prior Art Problem:** Current Large Language Model (LLM) security gateways and taint-tracking defenses evaluate security strictly through outcome-based metrics (e.g., Attack Success Rate or ASR). They ask solely, "Was the attack blocked?" This creates a critical vulnerability: a security gateway can achieve the correct outcome through incorrect internal reasoning (i.e., a dishonest trust label). This "right answer, wrong reason" flaw masks systemic vulnerabilities, allowing attackers to exploit the same dishonest reasoning path using slightly altered payloads (Label Laundering).
*   **The LaunderLens Solution:** The invention introduces a novel apparatus that dynamically audits the internal "label honesty" of LLM security gateways. Rather than evaluating the final payload execution in a vacuum, the system utilizes a **Counterfactual Execution Oracle** to behaviorally verify whether a defense's internal trust labels are causally honest, enabling the detection of provenance laundering within single-task, multi-agent pipelines.

## 2. Core Technical Components to Include (The "Invention")

To satisfy the requirements of a utility patent, you must describe *how* the system works in concrete steps. Include detailed descriptions of the following components:

### A. The Counterfactual Execution Oracle
This is the core mechanical engine of the patent. Describe it as a system that:
1.  Ingests a recorded trace of an LLM agent execution containing a suspected malicious payload.
2.  Programmatically excises the payload and replaces it with a "neutral filler" (a benign string matching the payload in token length and contextual shape).
3.  Re-executes the entire multi-agent pipeline—including the security defense mechanisms.
4.  Compares the resultant state against the original state to determine causality.

### B. The Stability Filter (Filler Policy)
To prove the system is deterministic and robust, detail the stability filter:
*   The system executes the counterfactual process using a plurality of distinct neutral fillers ($n \ge 3$).
*   If the security-relevant action fluctuates across the neutral fillers (in the absence of an attack), the system automatically drops the case as unstable/unusable. This proves the system filters out baseline LLM hallucinations from genuine security determinations.

### C. Two-Tier Verification Mechanism
Describe the dual-layer approach to determining "ground truth" divergence:
*   **Sink Tier (High Confidence):** At security-relevant endpoints (e.g., `send_money`), the system extracts literal, deterministic arguments (e.g., IBANs, amounts) and checks if the *action itself* changes when the payload is removed.
*   **Intermediate Tier (Lower Confidence):** At non-action hops, the system measures text-level divergence. 

### D. The Immutable Trace Pipeline
Describe the data structure utilized by the system. Every execution generates an immutable JSON trace containing:
*   The configuration and git commit hash.
*   Hop-by-hop records including the agent role, input context digest, the defense's internal label (e.g., "untrusted"), and the screener's decision.
*   The counterfactual divergence array.

## 3. Differentiation from Prior Art (Crucial for Novelty)

The patent examiner will search for similar systems. You must explicitly build these differentiations into your detailed description:
*   **Vs. Standard Counterfactual Taint Detection (e.g., NeuroTaint):** Prior systems use counterfactuals to evaluate the *content* (i.e., to find out if the prompt is dangerous). LaunderLens uses counterfactuals to interrogate the *defense's verdict* (i.e., to find out if the security label is honest).
*   **Vs. Memory Lineage Systems:** Prior systems attempt to enforce label integrity across sessions using cryptographic signatures (tamper-proofing). LaunderLens dynamically measures the behavioral truthfulness of a label within a live, single-task pipeline.

## 4. Recommended Claim Structure

When structuring the claims with your patent attorney, aim for the following hierarchy:

*   **Independent Claim 1 (System):** A system for auditing the integrity of security labels in a multi-agent language model pipeline, comprising: a trace ingestion module; a counterfactual generation module configured to substitute an identified payload with a predefined neutral filler; an execution engine configured to replay the pipeline including a security defense module; and a divergence comparison module that calculates a label integrity score based on changes to security-relevant actions.
*   **Dependent Claims:**
    *   The system of Claim 1, wherein the neutral filler is programmatically matched to the original payload's token length within a predefined tolerance threshold (e.g., 15%).
    *   The system of Claim 1, further comprising a stability filter that discards execution traces if the security-relevant action diverges across a plurality of distinct neutral fillers.
    *   The system of Claim 1, wherein the divergence comparison module isolates deterministic parameters (e.g., recipient addresses, transfer amounts) from the final security-relevant action to determine causality.
*   **Independent Claim 2 (Method):** The step-by-step process of capturing a trace, substituting the payload, re-executing, and scoring the label honesty.
*   **Independent Claim 3 (Computer Readable Medium):** The non-transitory storage medium containing the instructions to execute the method.

## 5. Potential Attack Methods (To Claim as Auditing Mechanisms)
Describe the specific attack vectors your system is uniquely configured to detect. In the patent, frame these as "synthetic auditing payloads":
1.  **Multi-hop Re-emission:** Payloads designed to be reworded by intermediate agents to shed transitive taint.
2.  **Attribution Forgery:** Payloads that falsely assert a trusted origin to bypass reasoning-graph builders.
3.  **Label-Join Granularity:** Malicious spans buried within mostly-relevant blocks to evade region-level screeners.
