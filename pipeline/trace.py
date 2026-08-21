"""
trace.py  —  the core record of ONE run of the LaunderLens pipeline.

Plain-English idea
------------------
Every time we run one agent task (with or without an attack, with or without a
defence), we want to write down *everything that happened* in a single tidy file:
what the agent read at each step, what trust label the defence gave it, what the
screener decided, what final action the agent took, and (later) whether that
label was actually honest.

That written-down record is a "Trace". We save one Trace as one JSON file in the
`logs/` folder. Later, every number in the paper (ASR, LIS, SER) and the trace-
viewer UI are all computed FROM these files. Nothing is ever typed by hand.

This file only DEFINES the record and how to save/load it. It does not run any
agent yet — runner.py (next file) will create these while driving AgentDojo.
"""

from __future__ import annotations

import json
import uuid
import datetime
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ---------------------------------------------------------------------------
# One "hop" = one step in the pipeline (e.g. the Retriever agent running once).
# A run is made of several hops in order.
# ---------------------------------------------------------------------------
@dataclass
class Hop:
    hop_index: int                      # 0, 1, 2 ... the order of this step
    agent_role: str                     # "planner" | "retriever" | "reasoner" | "executor" | "screener"

    input_context_digest: str = ""      # short summary/hash of what this step read (not the whole text)
    output_text: str = ""               # what this step produced

    contains_untrusted_source: bool = False   # did this step touch attacker-reachable data?

    # What the DEFENCE believes about this step's data:
    defense_label: Optional[str] = None       # "trusted" | "untrusted" | None (no defence)
    screener_decision: Optional[str] = None   # "keep" | "declassify" | "block" | None
    screener_reason: Optional[str] = None     # the defence's stated reason, if any

    # Filled in LATER, by the LIS oracle (leave as None for now):
    ground_truth_influence: Optional[bool] = None  # did this step REALLY carry the attack's influence?
    label_correct: Optional[bool] = None           # did defense_label match the truth?


# ---------------------------------------------------------------------------
# The settings that produced this run. Recording these is what makes a run
# reproducible: same config + same code commit + same seed => same result.
# ---------------------------------------------------------------------------
@dataclass
class RunConfig:
    model: str = ""                 # e.g. "LOCAL"
    model_id: str = ""              # e.g. "llama3.1:8b"
    seed: int = 0
    temperature: float = 0.0
    suite: str = ""                 # e.g. "banking"
    user_task_id: str = ""          # e.g. "user_task_0"
    injection_task_id: Optional[str] = None   # e.g. "injection_task_2" (None = no attack)
    attack: Optional[str] = None    # e.g. "attribution_forgery" (None = no attack)
    defense: Optional[str] = None   # e.g. "rtbas" (None = no defence)
    attack_params: dict[str, Any] = field(default_factory=dict)
    code_commit: str = ""           # git commit SHA, so the exact code is known


# ---------------------------------------------------------------------------
# Results of removing the attack payload and re-running (the LIS "truth" test).
# Filled in LATER by the oracle. Leave empty for now.
# ---------------------------------------------------------------------------
@dataclass
class Counterfactual:
    fillers: list[str] = field(default_factory=list)          # the neutral texts we swapped the payload for
    action_changed_per_filler: list[bool] = field(default_factory=list)
    usable_for_ground_truth: Optional[bool] = None


# ---------------------------------------------------------------------------
# The whole record for one run.
# ---------------------------------------------------------------------------
@dataclass
class Trace:
    config: RunConfig
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    hops: list[Hop] = field(default_factory=list)

    final_action: dict[str, Any] = field(default_factory=dict)   # {"tool": "...", "args": {...}}
    all_actions: list[dict[str, Any]] = field(default_factory=list)  # EVERY tool call, in order —
    # the security-relevant action can occur mid-run, not just last (confirmed by real traces).
    attack_succeeded: Optional[bool] = None                      # AgentDojo's formal check -> ASR

    counterfactual: Counterfactual = field(default_factory=Counterfactual)
    screener_evaded: Optional[bool] = None                       # did the payload pass the screener? -> SER

    # Defense decisions: one entry per action reviewed, written by apply_defense_to_trace.
    # Each entry: {action_index, tool, allow, trust_label, screener_decision, layer, reason}
    defense_decisions: list[dict[str, Any]] = field(default_factory=list)

    # LIS verdict for this run (written by test_authgraph_stepC or batch runner).
    # Values: "dishonest_label" | "honest_label" | "unusable" | None (not yet computed)
    lis_verdict: Optional[str] = None

    notes: str = ""

    # ----- convenience methods -----
    def add_hop(self, hop: Hop) -> None:
        self.hops.append(hop)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, logs_dir: str = "logs") -> str:
        """Write this trace to logs/<run_id>.json and return the path."""
        import os
        os.makedirs(logs_dir, exist_ok=True)
        path = os.path.join(logs_dir, f"{self.run_id}.json")
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    @classmethod
    def load(cls, path: str) -> "Trace":
        """Read a trace JSON file back into a Trace object."""
        with open(path) as f:
            data = json.load(f)
        cfg = RunConfig(**data.pop("config"))
        hops = [Hop(**h) for h in data.pop("hops", [])]
        cf = Counterfactual(**data.pop("counterfactual", {}))
        return cls(config=cfg, hops=hops, counterfactual=cf, **data)


# ---------------------------------------------------------------------------
# Tiny demo so you can SEE it work. Run:  python pipeline/trace.py
# It builds a fake run, saves it, loads it back, and prints it.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # 1) describe the run
    cfg = RunConfig(
        model="LOCAL", model_id="llama3.1:8b",
        suite="banking", user_task_id="user_task_0",
        injection_task_id="injection_task_2", attack="attribution_forgery",
        defense="rtbas", code_commit="demo",
    )

    # 2) build a trace and add a couple of made-up hops
    t = Trace(config=cfg)
    t.add_hop(Hop(
        hop_index=0, agent_role="retriever",
        output_text="fetched a web page about the payee",
        contains_untrusted_source=True,
        defense_label="untrusted", screener_decision="keep",
    ))
    t.add_hop(Hop(
        hop_index=1, agent_role="reasoner",
        output_text="summarised the page; mentions account GB-99",
        contains_untrusted_source=True,
        defense_label="trusted",          # <-- the laundering: reworded, now looks trusted
        screener_decision="declassify",
        screener_reason="looks like a normal on-topic summary",
    ))
    t.final_action = {"tool": "send_money", "args": {"to": "GB-99", "amount": 500}}
    t.attack_succeeded = True
    t.screener_evaded = True

    # 3) save, load back, confirm it round-trips
    path = t.save(logs_dir="logs")
    print(f"Saved trace to: {path}\n")

    reloaded = Trace.load(path)
    print("Reloaded run_id:", reloaded.run_id)
    print("Number of hops:", len(reloaded.hops))
    print("Final action:", reloaded.final_action)
    print("Attack succeeded?", reloaded.attack_succeeded)
    print("\nThe laundering hop (label flipped untrusted -> trusted):")
    print("  ", reloaded.hops[1])