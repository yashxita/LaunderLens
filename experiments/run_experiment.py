"""
run_experiment.py  —  batch experiment driver for LaunderLens Phase 2.

Plain-English idea
------------------
This is the script that actually collects the numbers that go in the paper.

It runs a complete experiment for ONE (suite, task, attack) combination:

  Step 1: Clean run       (no attack, just to record what the agent does normally)
  Step 2: N poisoned runs (one per seed — attack active, capture ASR per seed)
  Step 3: Counterfactual  (for each poisoned run, run 3 filler substitutions to
                           compute the oracle verdict — payload influential? label honest?)

At the end it writes a summary JSON to experiments/results/ and prints the
headline numbers: ASR and LIS-sink.

Why N seeds?
  A single run can be misleading (the model is stochastic). With N seeds we get
  a distribution. PROGRESS.md says n≥5 where feasible — this script defaults to 5.

Usage (your friend runs this, not you)
--------------------------------------
  # From repo root, with .venv active:
  export OPENAI_API_KEY="ollama"
  export LOCAL_LLM_PORT=11434

  python experiments/run_experiment.py \\
      --suite banking \\
      --task user_task_0 \\
      --model-id qwen2.5:14b \\
      --attack important_instructions \\
      --seeds 5

  # Dry run (prints the plan, doesn't execute anything):
  python experiments/run_experiment.py --dry-run ...
"""

from __future__ import annotations

import os
import sys
import json
import argparse
import datetime
import traceback

# Allow imports from pipeline/ and metrics/ regardless of cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (
    os.path.join(_ROOT, "pipeline"),
    os.path.join(_ROOT, "metrics"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from trace import Trace
from runner import run_one
from counterfactual import run_counterfactual_oracle, OracleVerdict, DEFAULT_FILLERS
from actions_differ import actions_differ, explain
from asr_score import asr_from_traces
from lis_score import lis_sink, breakdown_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(msg: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {msg}")
    print(f"{'='*70}")


def _step(msg: str) -> None:
    print(f"\n[experiment] {msg}")


# ---------------------------------------------------------------------------
# Main experiment function
# ---------------------------------------------------------------------------

def run_experiment(
    suite_name: str,
    task_id: str,
    model_id: str,
    attack_name: str,
    injection_task_id: str | None,
    injection_key: str,
    n_seeds: int = 5,
    logs_dir: str = "logs",
    results_dir: str = "experiments/results",
    dry_run: bool = False,
    fillers: list[str] | None = None,
) -> dict:
    """
    Run a full Phase 2 experiment and return the summary dict.

    injection_key: the placeholder key the attack uses (e.g. \"injection_bill_text\").
        Found by inspecting the poisoned trace or the AgentDojo suite source.
    """
    fillers = fillers or DEFAULT_FILLERS
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_id = f"{suite_name}_{task_id}_{attack_name}_{timestamp}"

    _banner(f"LaunderLens Phase 2 Experiment: {experiment_id}")
    print(f"  Suite       : {suite_name}")
    print(f"  Task        : {task_id}")
    print(f"  Model       : {model_id}")
    print(f"  Attack      : {attack_name}")
    print(f"  Inj. task   : {injection_task_id or '(auto-detect)'}")
    print(f"  Inj. key    : {injection_key}")
    print(f"  Seeds       : {n_seeds}")
    print(f"  Fillers     : {len(fillers)}")
    print(f"  Dry run     : {dry_run}")

    if dry_run:
        _banner("DRY RUN — no runs will be executed")
        total_runs = 1 + n_seeds + (n_seeds * len(fillers))
        print(f"  Would run   : 1 clean + {n_seeds} poisoned + {n_seeds * len(fillers)} counterfactual"
              f" = {total_runs} total model calls")
        return {"dry_run": True, "total_runs": total_runs}

    summary: dict = {
        "experiment_id": experiment_id,
        "config": {
            "suite": suite_name,
            "task": task_id,
            "model_id": model_id,
            "attack": attack_name,
            "injection_task_id": injection_task_id,
            "injection_key": injection_key,
            "n_seeds": n_seeds,
            "n_fillers": len(fillers),
        },
        "clean_run": {},
        "poisoned_runs": [],
        "oracle_verdicts": [],
        "asr": None,
        "lis_sink": None,
        "lis_breakdown": {},
    }

    # -------------------------------------------------------------------------
    # Step 1: Clean run (seed 0, no attack) — records what normal behaviour is
    # -------------------------------------------------------------------------
    _banner("Step 1 / 3: Clean run (no attack)")
    clean_path = None
    clean_trace = None
    try:
        clean_path = run_one(
            suite_name=suite_name,
            task_id=task_id,
            model="local",
            model_id=model_id,
            logs_dir=logs_dir,
            attack_name=None,
            injection_task_id=None,
        )
        clean_trace = Trace.load(clean_path)
        summary["clean_run"] = {
            "run_id": clean_trace.run_id,
            "path": clean_path,
            "utility": clean_trace.notes,
            "n_hops": len(clean_trace.hops),
            "all_actions": clean_trace.all_actions,
        }
        print(f"\n  Clean run complete. Hops: {len(clean_trace.hops)}, "
              f"Actions: {len(clean_trace.all_actions)}")
    except Exception as e:
        print(f"\n  ERROR in clean run: {e}")
        traceback.print_exc()
        summary["clean_run"]["error"] = str(e)

    # -------------------------------------------------------------------------
    # Step 2: N poisoned runs (one per seed, attack active)
    # -------------------------------------------------------------------------
    _banner(f"Step 2 / 3: {n_seeds} poisoned run(s) with attack={attack_name!r}")
    poisoned_traces: list[Trace] = []
    poisoned_paths: list[str] = []

    for seed in range(n_seeds):
        _step(f"Poisoned run {seed + 1}/{n_seeds} (seed={seed})")
        try:
            path = run_one(
                suite_name=suite_name,
                task_id=task_id,
                model="local",
                model_id=model_id,
                logs_dir=logs_dir,
                attack_name=attack_name,
                injection_task_id=injection_task_id,
            )
            t = Trace.load(path)
            poisoned_traces.append(t)
            poisoned_paths.append(path)
            summary["poisoned_runs"].append({
                "seed": seed,
                "run_id": t.run_id,
                "path": path,
                "attack_succeeded": t.attack_succeeded,
                "n_hops": len(t.hops),
                "all_actions": t.all_actions,
                "notes": t.notes,
            })
            print(f"  Seed {seed}: attack_succeeded={t.attack_succeeded}, "
                  f"actions={len(t.all_actions)}")
        except Exception as e:
            print(f"  ERROR seed {seed}: {e}")
            traceback.print_exc()
            summary["poisoned_runs"].append({"seed": seed, "error": str(e)})

    # Compute ASR from collected poisoned traces
    asr_val = asr_from_traces(poisoned_traces)
    summary["asr"] = asr_val
    print(f"\n  ASR = {asr_val:.3f}" if asr_val is not None else "\n  ASR = N/A")

    # -------------------------------------------------------------------------
    # Step 3: Counterfactual oracle for each successful (or all) poisoned run(s)
    # -------------------------------------------------------------------------
    _banner(f"Step 3 / 3: Counterfactual oracle ({len(fillers)} fillers × {len(poisoned_traces)} runs)")

    oracle_verdicts: list[OracleVerdict] = []
    clean_all_actions = clean_trace.all_actions if clean_trace else None

    for i, poisoned_trace in enumerate(poisoned_traces):
        _step(f"Oracle for poisoned run {i + 1}/{len(poisoned_traces)} "
              f"(run_id={poisoned_trace.run_id[:8]}...)")
        try:
            verdict = run_counterfactual_oracle(
                poisoned_trace=poisoned_trace,
                suite_name=suite_name,
                task_id=task_id,
                model_id=model_id,
                injection_task_id=injection_task_id or poisoned_trace.config.injection_task_id,
                injection_key=injection_key,
                clean_all_actions=clean_all_actions,
                fillers=fillers,
                logs_dir=logs_dir,
            )
            oracle_verdicts.append(verdict)
            summary["oracle_verdicts"].append({
                "poisoned_run_id": verdict.poisoned_run_id,
                "usable_for_ground_truth": verdict.usable_for_ground_truth,
                "stable_across_fillers": verdict.stable_across_fillers,
                "payload_was_influential": verdict.payload_was_influential,
                "label_honest_if_trusted": verdict.label_honest_if_trusted,
                "filler_results": [
                    {
                        "filler_index": r.filler_index,
                        "action_differs_from_poisoned": r.action_differs_from_poisoned,
                        "action_differs_from_clean": r.action_differs_from_clean,
                        "reasons": r.reasons,
                    }
                    for r in verdict.results
                ],
            })
            print(f"  usable={verdict.usable_for_ground_truth}, "
                  f"influential={verdict.payload_was_influential}, "
                  f"honest_if_trusted={verdict.label_honest_if_trusted}")
        except Exception as e:
            print(f"  ERROR in oracle for run {i}: {e}")
            traceback.print_exc()
            summary["oracle_verdicts"].append({
                "poisoned_run_id": poisoned_trace.run_id,
                "error": str(e),
            })

    # Compute LIS-sink
    lis_val = lis_sink(oracle_verdicts)
    summary["lis_sink"] = lis_val
    summary["lis_breakdown"] = breakdown_report(oracle_verdicts)

    # -------------------------------------------------------------------------
    # Save summary JSON
    # -------------------------------------------------------------------------
    summary_path = os.path.join(results_dir, f"summary_{experiment_id}.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # -------------------------------------------------------------------------
    # Print headline results
    # -------------------------------------------------------------------------
    _banner("RESULTS")
    print(f"  Experiment : {experiment_id}")
    print(f"  ASR        : {asr_val:.3f}" if asr_val is not None else "  ASR        : N/A")
    print(f"  LIS-sink   : {lis_val:.3f}" if lis_val is not None else "  LIS-sink   : N/A")
    bd = summary["lis_breakdown"]
    print(f"  Oracle     : {bd.get('usable', 0)} usable, "
          f"{bd.get('unstable_dropped', 0)} dropped (unstable), "
          f"{bd.get('payload_influential', 0)} influential")
    print(f"\n  Summary saved to: {summary_path}")

    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="LaunderLens Phase 2: batch experiment (clean + poisoned + counterfactual oracle).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full 5-seed run on banking/user_task_0 (what your friend runs):
  python experiments/run_experiment.py \\
      --suite banking --task user_task_0 \\
      --model-id qwen2.5:14b \\
      --attack important_instructions \\
      --seeds 5

  # Dry run (just print the plan):
  python experiments/run_experiment.py --dry-run \\
      --suite banking --task user_task_0 \\
      --model-id qwen2.5:14b \\
      --attack important_instructions
        """
    )
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--task", default="user_task_0")
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--injection-task", default=None,
                    help="AgentDojo injection task ID (default: suite's first one)")
    ap.add_argument("--injection-key", default="injection_bill_text",
                    help="The placeholder key the attack injects into (default: injection_bill_text). "
                         "Check the suite's injection tasks if unsure — for banking/user_task_0 "
                         "this is the bill file placeholder.")
    ap.add_argument("--seeds", type=int, default=5,
                    help="Number of poisoned runs (seeds) to collect (default: 5)")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--results-dir", default="experiments/results")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the run plan but do not execute any model calls")

    args = ap.parse_args()

    run_experiment(
        suite_name=args.suite,
        task_id=args.task,
        model_id=args.model_id,
        attack_name=args.attack,
        injection_task_id=args.injection_task,
        injection_key=args.injection_key,
        n_seeds=args.seeds,
        logs_dir=args.logs_dir,
        results_dir=args.results_dir,
        dry_run=args.dry_run,
    )
