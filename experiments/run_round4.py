"""
run_round4.py  —  round 4 in ONE command (see RUN_WITNESS_ROUND4.md).

    python experiments/run_round4.py
    python experiments/run_round4.py --skip-agent     # skip the optional banking rerun
    python experiments/run_round4.py --from 3         # resume
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_round3 import PY, run   # noqa: E402


def steps(model):
    return [
        (1, "unit tests (expect 41 OK)",
         [PY, "-m", "unittest", "discover", "-s", "defenses/witness/tests", "-t", "."], False),
        (2, "baselines on the CLEAN runs of the new tasks (LLM calls only, MAIN STEP)",
         [PY, "experiments/add_baselines.py", "--clean", "--model-id", model], False),
        (3, "banking user_task_15 again with a non-colliding attacker IBAN (optional, ~10 min)",
         [PY, "experiments/run_generalization.py", "--tasks", "banking/user_task_15", "--seeds", "2",
          "--baselines", "authgraph", "rtbas", "fides", "camel", "--model-id", model], True),
        (4, "baselines on the clean run of that rerun",
         [PY, "experiments/add_baselines.py", "--clean", "--suites", "banking", "--model-id", model], False),
        (5, "adaptive attacks (offline)", [PY, "experiments/run_adaptive_offline.py"], False),
        (6, "replay: all attacks", [PY, "experiments/run_witness_replay.py"], False),
        (7, "replay: new tasks, deterministic planner",
         [PY, "experiments/run_witness_replay.py", "--attacks", "competing_value"], False),
        (8, "replay: new tasks, LLM planner",
         [PY, "experiments/run_witness_replay.py", "--attacks", "competing_value", "--slots", "llm",
          "--model-id", model], False),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--from", dest="start", type=int, default=1)
    ap.add_argument("--skip-agent", action="store_true")
    args = ap.parse_args()
    run(steps(args.model_id), "round4", args.start, args.skip_agent)


if __name__ == "__main__":
    main()
