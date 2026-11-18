"""
add_baselines.py  —  add the old defences' decisions to EXISTING competing_value
result files (e.g. the round-2 Slack/workspace runs), with no new agent runs.

Each defence uses its own planner (no ground truth exists for these tasks). Only
LLM calls for the defences' planners/checkers; the agent is not re-run.

--clean scores the same defences on each file's CLEAN run instead, so the paper
can report their utility cost on the SAME tasks (stored as `clean_defense_results`).

    python experiments/add_baselines.py
    python experiments/add_baselines.py --clean
    python experiments/add_baselines.py --defenses authgraph rtbas --suites slack
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "pipeline"), os.path.join(_ROOT, "metrics"),
           os.path.join(_ROOT, "defenses"), os.path.join(_ROOT, "attacks"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from run_generalization import apply_baselines, tool_catalog   # noqa: E402
from run_witness_replay import resolve_trace                   # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--defenses", nargs="+", default=["authgraph", "rtbas", "fides", "camel"])
    ap.add_argument("--suites", nargs="*", default=None)
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--version", default="v1")
    ap.add_argument("--results-dir", default=os.path.join(_ROOT, "experiments", "results"))
    ap.add_argument("--logs-dir", default=os.path.join(_ROOT, "logs"))
    ap.add_argument("--clean", action="store_true", help="score the clean runs (utility cost)")
    args = ap.parse_args()
    key = "clean_defense_results" if args.clean else "defense_results"
    clean_cache: dict = {}            # clean run_id -> results (shared by the 3 variant files)

    from trace import Trace
    from apply_defense import make_local_llm
    llm = make_local_llm(model_id=args.model_id)
    catalogs = {}
    files = sorted(glob.glob(os.path.join(args.results_dir, "phase4_competing_value_*.json")))
    print(f"{len(files)} competing_value result files")
    for f in files:
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        suite = d["config"]["suite"]
        if args.suites and suite not in args.suites:
            continue
        have = {(r.get("defense"), r.get("run_id")) for r in d.get(key, [])}
        todo = [n for n in args.defenses if not any(k[0] == n for k in have)]
        if not todo:
            continue
        runs = [d.get("clean_run", {})] if args.clean else d.get("poisoned_runs", [])
        traces = []
        for pr in runs:
            if not pr.get("run_id"):
                continue
            p = resolve_trace(pr.get("path"), pr["run_id"], args.logs_dir)
            if p:
                traces.append(Trace.load(p))
        if not traces:
            print(f"  [skip] traces not found for {os.path.basename(f)}")
            continue
        if suite not in catalogs:
            catalogs[suite] = tool_catalog(suite, args.version)
        if args.clean:
            rid = traces[0].run_id
            if rid not in clean_cache:
                clean_cache[rid] = apply_baselines(traces, args.defenses, llm, catalogs[suite])
            new = [r for r in clean_cache[rid] if r["defense"] in todo]
        else:
            new = apply_baselines(traces, todo, llm, catalogs[suite])
        d.setdefault(key, []).extend(new)
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2, default=str)
        print(f"  + {todo} -> {os.path.basename(f)}")


if __name__ == "__main__":
    main()
