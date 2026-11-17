"""
run_round3.py  —  everything for round 3 in ONE command (see RUN_WITNESS_ROUND3.md).

Runs the steps in order, keeps going if one fails, and writes the full console
output to experiments/results/round3_log_<ts>.txt.

    python experiments/run_round3.py                 # everything
    python experiments/run_round3.py --skip-agent    # only the steps with no agent runs
    python experiments/run_round3.py --from 5        # resume at step 5
"""

from __future__ import annotations

import argparse
import datetime
import os
import subprocess
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def steps(model, max_tasks):
    gen = [PY, "experiments/run_generalization.py", "--suites", "banking", "--seeds", "2",
           "--baselines", "authgraph", "rtbas", "fides", "camel", "--model-id", model]
    if max_tasks:
        gen += ["--max-tasks", str(max_tasks)]
    return [
        # (number, title, command, needs agent runs?)
        (1, "unit tests (expect 39 OK)",
         [PY, "-m", "unittest", "discover", "-s", "defenses/witness/tests", "-t", "."], False),
        (2, "find delegated-value tasks (fixed finder)",
         [PY, "experiments/find_delegated_tasks.py"], False),
        (3, "dry run: which banking tasks / how many agent runs",
         [PY, "experiments/run_generalization.py", "--suites", "banking", "--dry-run"], False),
        (4, "banking generalisation + 4 baselines (MAIN COMPUTE)", gen, True),
        (5, "baselines on the round-2 Slack/workspace runs (LLM calls only)",
         [PY, "experiments/add_baselines.py", "--model-id", model], False),
        (6, "adaptive attacks, fully compromised agent (offline, seconds)",
         [PY, "experiments/run_adaptive_offline.py"], False),
        (7, "replay: all attacks, deterministic planner",
         [PY, "experiments/run_witness_replay.py"], False),
        (8, "replay: new tasks only, deterministic planner",
         [PY, "experiments/run_witness_replay.py", "--attacks", "competing_value"], False),
        (9, "replay: new tasks only, LLM planner",
         [PY, "experiments/run_witness_replay.py", "--attacks", "competing_value", "--slots", "llm",
          "--model-id", model], False),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--max-tasks", type=int, default=0, help="cap banking tasks in step 4")
    ap.add_argument("--from", dest="start", type=int, default=1)
    ap.add_argument("--skip-agent", action="store_true")
    args = ap.parse_args()

    os.chdir(_ROOT)
    os.makedirs("experiments/results", exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join("experiments", "results", f"round3_log_{stamp}.txt")
    summary = []
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    with open(log_path, "w", encoding="utf-8") as log:
        for n, title, cmd, agent in steps(args.model_id, args.max_tasks):
            if n < args.start or (agent and args.skip_agent):
                continue
            head = f"\n{'=' * 72}\n STEP {n}: {title}\n $ {' '.join(cmd)}\n{'=' * 72}\n"
            print(head, end="")
            log.write(head)
            t0 = time.time()
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="replace", env=env)
            for line in p.stdout:
                print(line, end="")
                log.write(line)
            p.wait()
            mins = (time.time() - t0) / 60
            status = "OK" if p.returncode == 0 else f"FAILED (exit {p.returncode})"
            summary.append(f"step {n}: {status:20s} {mins:6.1f} min  {title}")
            log.flush()
        tail = "\n\nSUMMARY\n" + "\n".join(summary) + f"\n\nfull log: {log_path}\n"
        print(tail)
        log.write(tail)


if __name__ == "__main__":
    main()
