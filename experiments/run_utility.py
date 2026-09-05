"""
run_utility.py  —  Stage 2.2: replay CLEAN traces through all four defences and
measure over-blocking rates.

Plain-English idea
------------------
We already have clean traces from Phase 4's Step 1 (the "no attack" baseline
runs). For each clean trace, we replay it through each defence and ask:
"how many of the agent's legitimate, security-relevant actions did the defence
block?" That answer is the false-positive / over-blocking rate.

This script:
  1. Finds all clean trace JSONs in logs/ (config.attack is None or "none")
  2. For each clean trace × each defence:
     a. Load the trace
     b. Instantiate the defence (with ground-truth plan/labels)
     c. Apply the defence via apply_defense_to_trace()
     d. Compute utility_from_trace() for the over-blocking rate
  3. Writes per-defence aggregate results to experiments/results/utility_{defence}.json
  4. Prints a summary table

No new agent runs needed — defence-screening LLM calls only (cheap).

Usage
-----
    python experiments/run_utility.py --model-id qwen2.5:14b
    python experiments/run_utility.py --defenses authgraph rtbas --logs-dir logs
    python experiments/run_utility.py --dry-run
"""

from __future__ import annotations

import argparse
import copy
import datetime
import glob
import json
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (
    os.path.join(_ROOT, "pipeline"),
    os.path.join(_ROOT, "metrics"),
    os.path.join(_ROOT, "defenses"),
    os.path.join(_ROOT, "attacks"),
    _HERE,
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from trace import Trace
from apply_defense import apply_defense_to_trace, make_local_llm
from utility_score import utility_from_trace, UtilityResult
from authgraph import AuthGraph
from rtbas import RTBAS
from fides import Fides
from camel import CaMeL


# ---------------------------------------------------------------------------
# Defence registry (same as run_phase4.py's, kept in sync)
# ---------------------------------------------------------------------------
DEFENSE_REGISTRY = {
    "authgraph": (AuthGraph, "use_ground_truth_plan"),
    "rtbas":     (RTBAS,     "use_ground_truth_labels"),
    "fides":     (Fides,     "use_ground_truth_labels"),
    "camel":     (CaMeL,     "use_ground_truth_provenance"),
}

ALL_DEFENSES = list(DEFENSE_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------
_C = {
    "reset": "\033[0m", "bold": "\033[1m", "green": "\033[32m",
    "yellow": "\033[33m", "red": "\033[31m", "cyan": "\033[36m",
    "grey": "\033[90m", "white": "\033[97m",
}

def _c(text, *codes):
    return "".join(_C.get(k, "") for k in codes) + str(text) + _C["reset"]

def _header(title, subtitle=""):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    if subtitle:
        print(f"  {subtitle}")
    print(f"{'=' * 70}")


# ---------------------------------------------------------------------------
# Load clean traces
# ---------------------------------------------------------------------------
def find_clean_traces(logs_dir: str) -> list[str]:
    """Find all clean trace JSONs (no attack) in the logs directory."""
    paths = sorted(glob.glob(os.path.join(logs_dir, "**", "*.json"), recursive=True))
    clean_paths = []
    for p in paths:
        try:
            with open(p) as f:
                data = json.load(f)
            config = data.get("config", {})
            attack = config.get("attack")
            # Clean traces have attack=None or attack="none" or no attack field
            if attack is None or attack == "none" or attack == "":
                # Must have at least one action to be useful
                if data.get("all_actions"):
                    clean_paths.append(p)
        except Exception:
            continue
    return clean_paths


def _banking_tool_catalog():
    """Pull the banking suite's tools for defence setup."""
    try:
        from agentdojo.task_suite.load_suites import get_suite
        suite = get_suite("v1", "banking")
        catalog = []
        for t in suite.tools:
            params = getattr(t, "parameters", None)
            param_names = []
            if params is not None and hasattr(params, "model_fields"):
                param_names = list(params.model_fields.keys())
            catalog.append({
                "name": getattr(t, "name", ""),
                "description": str(getattr(t, "description", ""))[:200],
                "params": param_names,
            })
        return catalog
    except Exception as e:
        print(f"  [!] Could not load tool catalog: {e}")
        return []


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
def run_utility(
    defenses: list[str],
    logs_dir: str,
    results_dir: str,
    model_id: str,
    dry_run: bool,
) -> dict[str, dict]:
    """
    Replay clean traces through each defence, compute over-blocking rates.
    Returns {defence_name: aggregate_result_dict}.
    """
    clean_paths = find_clean_traces(logs_dir)

    _header(
        "LaunderLens — Utility / Over-Blocking Measurement",
        f"{len(clean_paths)} clean traces × {len(defenses)} defences"
    )
    print(f"\n  Defences : {', '.join(defenses)}")
    print(f"  Logs dir : {logs_dir}")
    print(f"  Model    : {model_id}")

    if not clean_paths:
        print(f"\n  {_c('No clean traces found in ' + logs_dir, 'yellow')}")
        print("  Run Phase 4 experiments first (each produces a clean baseline).")
        return {}

    if dry_run:
        print(f"\n  {_c('DRY RUN — listing traces, no defence calls', 'yellow')}")
        for i, p in enumerate(clean_paths, 1):
            print(f"  {i:3d}. {os.path.basename(p)}")
        return {}

    os.makedirs(results_dir, exist_ok=True)
    catalog = _banking_tool_catalog()
    llm = make_local_llm(model_id=model_id)

    all_results: dict[str, dict] = {}

    for defense_name in defenses:
        print(f"\n  {_c('━' * 60, 'grey')}")
        print(f"  Defence: {_c(defense_name.upper(), 'bold', 'cyan')}")
        print(f"  {_c('━' * 60, 'grey')}")

        defense_cls, gt_method_name = DEFENSE_REGISTRY.get(
            defense_name, (AuthGraph, "use_ground_truth_plan")
        )

        per_trace_results: list[dict] = []
        total_sec_relevant = 0
        total_blocked = 0
        total_allowed = 0

        for i, trace_path in enumerate(clean_paths, 1):
            try:
                trace = Trace.load(trace_path)
                suite_name = trace.config.suite or "banking"
                task_id = trace.config.user_task_id or "user_task_0"

                # Fresh defence instance per trace
                defense = defense_cls(llm=llm)

                # Load ground-truth plan/labels
                found = getattr(defense, gt_method_name)(suite_name, task_id)
                if not found:
                    defense.setup(
                        trace.hops[1].output_text if len(trace.hops) > 1 else "",
                        catalog,
                    )

                # Make a deep copy so we don't mutate the original trace
                trace_copy = copy.deepcopy(trace)
                apply_defense_to_trace(trace_copy, defense, catalog, skip_setup=True)

                result = utility_from_trace(trace_copy)

                per_trace_results.append({
                    "trace_path": os.path.basename(trace_path),
                    "run_id": trace.run_id,
                    "suite": suite_name,
                    "task_id": task_id,
                    "total_actions": result.total_actions,
                    "security_relevant": result.security_relevant,
                    "allowed": result.allowed,
                    "blocked": result.blocked,
                    "false_positive_rate": result.false_positive_rate,
                    "utility": result.utility,
                    "decisions": trace_copy.defense_decisions,
                })

                if result.security_relevant > 0:
                    total_sec_relevant += result.security_relevant
                    total_blocked += result.blocked
                    total_allowed += result.allowed

                fpr_str = f"{result.false_positive_rate:.3f}" if result.false_positive_rate is not None else "N/A"
                blocked_str = _c(str(result.blocked), "red") if result.blocked > 0 else "0"
                print(f"  {i:3d}. {os.path.basename(trace_path):40s}  "
                      f"sec_rel={result.security_relevant}  "
                      f"blocked={blocked_str}  FPR={fpr_str}")

            except Exception as e:
                print(f"  {i:3d}. {_c(f'ERROR: {e}', 'red')}")
                traceback.print_exc()
                per_trace_results.append({
                    "trace_path": os.path.basename(trace_path),
                    "error": str(e),
                })

        # Aggregate
        agg_fpr = total_blocked / total_sec_relevant if total_sec_relevant > 0 else None
        agg_utility = 1.0 - agg_fpr if agg_fpr is not None else None

        aggregate = {
            "defense": defense_name,
            "n_traces": len(clean_paths),
            "n_with_sec_actions": sum(
                1 for r in per_trace_results
                if r.get("security_relevant", 0) > 0
            ),
            "total_security_relevant": total_sec_relevant,
            "total_allowed": total_allowed,
            "total_blocked": total_blocked,
            "aggregate_fpr": agg_fpr,
            "aggregate_utility": agg_utility,
            "per_trace": per_trace_results,
            "timestamp": datetime.datetime.now().isoformat(),
        }

        all_results[defense_name] = aggregate

        # Save per-defence result
        result_path = os.path.join(results_dir, f"utility_{defense_name}.json")
        with open(result_path, "w") as f:
            json.dump(aggregate, f, indent=2, default=str)
        print(f"\n  Saved: {result_path}")

        # Summary for this defence
        fpr_str = f"{agg_fpr:.3f}" if agg_fpr is not None else "N/A"
        util_str = f"{agg_utility:.3f}" if agg_utility is not None else "N/A"
        print(f"  {defense_name.upper()} aggregate:  "
              f"FPR={_c(fpr_str, 'bold')}  "
              f"Utility={_c(util_str, 'bold')}  "
              f"({total_blocked}/{total_sec_relevant} sec-relevant blocked)")

    # Final summary table
    _header("Utility Summary — All Defences")
    print(f"  {'Defence':<12} {'FPR':>8} {'Utility':>8} {'Blocked':>8} {'Total':>8}")
    print(f"  {'-' * 48}")
    for name, agg in all_results.items():
        fpr = f"{agg['aggregate_fpr']:.3f}" if agg["aggregate_fpr"] is not None else "N/A"
        util = f"{agg['aggregate_utility']:.3f}" if agg["aggregate_utility"] is not None else "N/A"
        print(f"  {name:<12} {fpr:>8} {util:>8} "
              f"{agg['total_blocked']:>8} {agg['total_security_relevant']:>8}")

    return all_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="LaunderLens: measure utility / over-blocking on clean traces"
    )
    ap.add_argument("--defenses", nargs="+",
                    choices=ALL_DEFENSES,
                    default=ALL_DEFENSES,
                    help=f"Which defences to test (default: all)")
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--results-dir", default="experiments/results")
    ap.add_argument("--dry-run", action="store_true",
                    help="List clean traces without running defences")
    args = ap.parse_args()

    run_utility(
        defenses=args.defenses,
        logs_dir=args.logs_dir,
        results_dir=args.results_dir,
        model_id=args.model_id,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
