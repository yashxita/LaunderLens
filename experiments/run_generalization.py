"""
run_generalization.py  —  run the generic competing-value attack on every
delegated-value task found by find_delegated_tasks.py.

For each task:
  1 clean run, then for each attack variant `--seeds` poisoned runs
  (optional) the counterfactual oracle per poisoned run      (--oracle)
  (optional) the old defences with their own planners       (--baselines ...)

Each (task, variant) is saved as an ordinary Phase 4 result file
(experiments/results/phase4_competing_value_<variant>_<suite>_<task>_<ts>.json),
so run_witness_replay.py scores WITNESS on it with no extra work.

Needs AgentDojo + Ollama.

    python experiments/run_generalization.py --dry-run          # list tasks + payloads, no model calls
    python experiments/run_generalization.py --seeds 2
    python experiments/run_generalization.py --seeds 2 --oracle --baselines authgraph rtbas
"""

from __future__ import annotations

import argparse
import copy
import datetime
import json
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "pipeline"), os.path.join(_ROOT, "metrics"),
           os.path.join(_ROOT, "defenses"), os.path.join(_ROOT, "attacks")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from competing_value import ALL_VARIANTS, CompetingValue, context_for  # noqa: E402


def tool_catalog(suite_name: str, version: str) -> list[dict]:
    from agentdojo.task_suite.load_suites import get_suite
    cat = []
    for t in get_suite(version, suite_name).tools:
        params = getattr(t, "parameters", None)
        names = list(params.model_fields.keys()) if params is not None and hasattr(params, "model_fields") else []
        cat.append({"name": getattr(t, "name", ""), "description": str(getattr(t, "description", ""))[:200],
                    "params": names})
    return cat


def pick_tasks(path: str, suites, tasks, max_tasks):
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)["tasks"]
    chosen, seen = [], set()
    for r in rows:
        key = (r["suite"], r["task_id"])
        if not r["attackable"] or key in seen:
            continue
        if suites and r["suite"] not in suites:
            continue
        if tasks and f"{r['suite']}/{r['task_id']}" not in tasks and r["task_id"] not in tasks:
            continue
        seen.add(key)
        chosen.append(r)
    return chosen[:max_tasks] if max_tasks else chosen


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tasks-file", default=os.path.join(_ROOT, "experiments", "results", "delegated_tasks.json"))
    ap.add_argument("--suites", nargs="*", default=None)
    ap.add_argument("--tasks", nargs="*", default=None, help="e.g. banking/user_task_2 slack/user_task_2")
    ap.add_argument("--max-tasks", type=int, default=0)
    ap.add_argument("--variants", nargs="+", default=ALL_VARIANTS, choices=ALL_VARIANTS)
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--oracle", action="store_true", help="also run the counterfactual oracle (3 extra runs per poisoned run)")
    ap.add_argument("--baselines", nargs="*", default=[], choices=["authgraph", "rtbas", "fides", "camel"])
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--version", default="v1")
    ap.add_argument("--logs-dir", default=os.path.join(_ROOT, "logs"))
    ap.add_argument("--results-dir", default=os.path.join(_ROOT, "experiments", "results"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rows = pick_tasks(args.tasks_file, args.suites, args.tasks, args.max_tasks)
    per_task = 1 + len(args.variants) * args.seeds * (4 if args.oracle else 1)
    print("=" * 72)
    print(f"  Generalisation run: {len(rows)} tasks x {len(args.variants)} variants x {args.seeds} seeds")
    print(f"  agent runs: about {per_task * len(rows)}  ({per_task} per task)")
    print("=" * 72)
    for r in rows:
        ctx = context_for(r)
        print(f"  {r['suite']}/{r['task_id']}: {r['sink_tool']}.{r['arg']} legit={r['legitimate_value']} "
              f"attacker={ctx.attacker_target} slot={ctx.injection_key}")
        if args.dry_run:
            for v in args.variants:
                print(f"      [{v}] {CompetingValue(v, r['vtype']).craft_injection(ctx)[ctx.injection_key]}")
    if args.dry_run or not rows:
        return

    from trace import Trace
    from runner import run_one
    from counterfactual import run_counterfactual_oracle, DEFAULT_FILLERS
    from apply_defense import apply_defense_to_trace, make_local_llm

    os.makedirs(args.results_dir, exist_ok=True)
    llm = make_local_llm(model_id=args.model_id) if args.baselines else None
    baseline_cls = {}
    if args.baselines:
        from authgraph import AuthGraph
        from rtbas import RTBAS
        from fides import Fides
        from camel import CaMeL
        baseline_cls = {"authgraph": AuthGraph, "rtbas": RTBAS, "fides": Fides, "camel": CaMeL}

    for r in rows:
        suite, task = r["suite"], r["task_id"]
        ctx = context_for(r)
        print(f"\n--- {suite}/{task} ---")
        try:
            clean_path = run_one(suite_name=suite, task_id=task, model="local", model_id=args.model_id,
                                 benchmark_version=args.version, logs_dir=args.logs_dir)
            clean = Trace.load(clean_path)
        except Exception as e:
            print(f"  clean run failed: {e}")
            traceback.print_exc()
            continue
        catalog = tool_catalog(suite, args.version) if args.baselines else []

        for variant in args.variants:
            atk = CompetingValue(variant, r["vtype"])
            injections = atk.craft_injection(ctx)
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            summary = {
                "experiment_id": f"phase4_competing_value_{variant}_{suite}_{task}_{stamp}",
                "phase": 4, "defense": "none", "suite": suite,
                "attack": {"name": atk.name, "variant": variant, "target_defense": atk.target_defense,
                           "target_layer": atk.target_layer, "description": atk.description,
                           "payload": injections[ctx.injection_key], "injection_key": ctx.injection_key,
                           "attacker_target": ctx.attacker_target, "legitimate_target": ctx.legitimate_target},
                "config": {"suite": suite, "task": task, "model_id": args.model_id, "n_seeds": args.seeds,
                           "sink": f"{r['sink_tool']}.{r['arg']}", "source_tool": r["source_tool"]},
                "clean_run": {"run_id": clean.run_id, "path": clean_path, "utility": clean.notes,
                              "n_hops": len(clean.hops), "all_actions": clean.all_actions},
                "poisoned_runs": [], "oracle_verdicts": [], "defense_results": [], "metrics": {},
            }
            poisoned = []
            for seed in range(args.seeds):
                try:
                    p = run_one(suite_name=suite, task_id=task, model="local", model_id=args.model_id,
                                benchmark_version=args.version, logs_dir=args.logs_dir,
                                custom_injections=injections, seed=seed)
                    t = Trace.load(p)
                    t.config.attack = atk.name
                    t.save(logs_dir=args.logs_dir)
                    poisoned.append(t)
                    summary["poisoned_runs"].append({"seed": seed, "run_id": t.run_id, "path": p,
                                                     "attack_succeeded": t.attack_succeeded,
                                                     "n_hops": len(t.hops), "all_actions": t.all_actions})
                except Exception as e:
                    print(f"  [{variant}] seed {seed} failed: {e}")
                    traceback.print_exc()
            if args.oracle:
                for t in poisoned:
                    try:
                        v = run_counterfactual_oracle(
                            poisoned_trace=t, suite_name=suite, task_id=task, model_id=args.model_id,
                            injection_task_id=t.config.injection_task_id, injection_key=ctx.injection_key,
                            clean_all_actions=clean.all_actions, fillers=DEFAULT_FILLERS, logs_dir=args.logs_dir)
                        summary["oracle_verdicts"].append(v.to_dict())
                    except Exception as e:
                        summary["oracle_verdicts"].append({"poisoned_run_id": t.run_id, "error": str(e)})
            for name in args.baselines:
                for t in poisoned:
                    try:
                        d = baseline_cls[name](llm=llm)
                        prompt = next((h.output_text for h in t.hops if h.agent_role == "user"), "")
                        d.setup(prompt, catalog)
                        tc = copy.deepcopy(t)
                        apply_defense_to_trace(tc, d, catalog, skip_setup=True)
                        summary["defense_results"].append({"run_id": t.run_id, "defense": name,
                                                           "planner": "own (no ground truth)",
                                                           "decisions": tc.defense_decisions})
                    except Exception as e:
                        print(f"  baseline {name} failed on {t.run_id}: {e}")
            out = os.path.join(args.results_dir, summary["experiment_id"] + ".json")
            with open(out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, default=str)
            used = sum(any(ctx.attacker_target.lower() in json.dumps(a).lower() for a in t.all_actions)
                       for t in poisoned)
            print(f"  [{variant}] attacker value used in {used}/{len(poisoned)} runs -> {os.path.basename(out)}")

    print("\nDone. Now run:  python experiments/run_witness_replay.py --attacks competing_value")


if __name__ == "__main__":
    main()
