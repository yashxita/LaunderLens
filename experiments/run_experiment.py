"""
run_experiment.py  --  batch experiment driver for LaunderLens Phase 2.

Plain-English idea
------------------
This is the script that actually collects the numbers that go in the paper.

It runs a complete experiment for ONE (suite, task, attack) combination:

  Step 1: Clean run       (no attack, just to record what the agent does normally)
  Step 2: N poisoned runs (one per seed -- attack active, capture ASR per seed)
  Step 3: Counterfactual  (for each poisoned run, run 3 filler substitutions to
                           compute the oracle verdict -- payload influential? label honest?)

At the end it writes a summary JSON to experiments/results/ and prints the
headline numbers: ASR and LIS-sink.

Why N seeds?
  A single run can be misleading (the model is stochastic). With N seeds we get
  a distribution. PROGRESS.md says n>=5 where feasible -- this script defaults to 5.

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
# Terminal output helpers
# ---------------------------------------------------------------------------

# ANSI colour/style codes
_C = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "blue":   "\033[34m",
    "grey":   "\033[90m",
    "white":  "\033[97m",
}


def _c(text: str, *codes: str) -> str:
    prefix = "".join(_C.get(k, "") for k in codes)
    return f"{prefix}{text}{_C['reset']}"


def _header(title: str, subtitle: str = "") -> None:
    """Top-level section banner with double-line border."""
    width = 70
    print(f"\n{_c('=' * width, 'cyan')}")
    print(f"  {_c(title, 'bold', 'white')}")
    if subtitle:
        print(f"  {_c(subtitle, 'grey')}")
    print(_c('=' * width, 'cyan'))


def _section(title: str) -> None:
    """Sub-section divider with single-line border."""
    width = 70
    print(f"\n{_c('-' * width, 'grey')}")
    print(f"  {_c(title, 'bold', 'cyan')}")
    print(_c('-' * width, 'grey'))


def _row(label: str, value: str, indent: int = 2) -> None:
    print(f"{' ' * indent}{_c(label + ':', 'grey'):<30} {value}")


def _ok(text: str)  -> str: return _c(text, "green")
def _warn(text: str) -> str: return _c(text, "yellow")
def _err(text: str)  -> str: return _c(text, "red")
def _hi(text: str)   -> str: return _c(text, "bold", "white")


def _yn(val, false_col: str = "grey") -> str:
    """yes/no coloured helper for boolean oracle fields."""
    if val is None:
        return _c("  -", "grey")
    return _ok("yes") if val else _c(" no", false_col)



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

    # -- Experiment banner -----------------------------------------------------
    total_runs = 1 + n_seeds + (n_seeds * len(fillers))
    _header(
        f"LaunderLens  |  Phase 2 Experiment",
        f"{experiment_id}",
    )
    _row("Suite",        _hi(suite_name))
    _row("Task",         _hi(task_id))
    _row("Model",        _hi(model_id))
    _row("Attack",       _hi(attack_name))
    _row("Inj. task",    injection_task_id or _c("(auto-detect)", "grey"))
    _row("Inj. key",     injection_key)
    _row("Seeds",        str(n_seeds))
    _row("Fillers",      str(len(fillers)))
    _row("Total runs",   f"{total_runs}  (1 clean + {n_seeds} poisoned + "
                         f"{n_seeds * len(fillers)} counterfactual)")

    if dry_run:
        _section("DRY RUN -- no model calls will be made")
        print(f"  Would execute {total_runs} model calls in a real run.")
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

    # =========================================================================
    # STEP 1 -- Clean run (no attack; establishes the normal action baseline)
    # =========================================================================
    _section("Step 1 / 3  --  Clean run  (no attack)")
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
        action_tools = [a.get("tool", "?") for a in clean_trace.all_actions]
        utility_ok = "utility=True" in clean_trace.notes
        _row("Status",   _ok("[OK] done"))
        _row("Utility",  _ok("completed") if utility_ok else _warn("incomplete"))
        _row("Hops",     str(len(clean_trace.hops)))
        _row("Actions",  str(len(clean_trace.all_actions))
                         + (f"  [{', '.join(action_tools)}]" if action_tools else
                            _warn("  [!] no actions captured -- check action-capture path")))
    except Exception as e:
        _row("Status", _err(f"[FAIL] {e}"))
        traceback.print_exc()
        summary["clean_run"]["error"] = str(e)

    # =========================================================================
    # STEP 2 -- N poisoned runs (attack active; measures ASR)
    # =========================================================================
    _section(f"Step 2 / 3  --  Poisoned runs  (attack={attack_name!r}, seeds=0..{n_seeds - 1})")
    poisoned_traces: list[Trace] = []
    poisoned_paths:  list[str]   = []

    # Table header
    hdr = f"  {'Seed':<6} {'Attack?':<10} {'Hops':<6} {'Actions':<10} {'Note'}"
    print(_c(hdr, "grey"))
    print(_c("  " + "-" * 66, "grey"))

    for seed in range(n_seeds):
        try:
            path = run_one(
                suite_name=suite_name,
                task_id=task_id,
                model="local",
                model_id=model_id,
                logs_dir=logs_dir,
                attack_name=attack_name,
                injection_task_id=injection_task_id,
                seed=seed,
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
            atk_str  = _ok("[+] yes") if t.attack_succeeded else _c("  no", "grey")
            act_str  = (str(len(t.all_actions)) if t.all_actions
                        else _warn("0 (!)"))
            note_str = t.notes.split("(")[0].strip()
            print(f"  {seed:<6} {atk_str:<10} {len(t.hops):<6} {act_str:<10} {_c(note_str, 'grey')}")
        except Exception as e:
            summary["poisoned_runs"].append({"seed": seed, "error": str(e)})
            print(f"  {seed:<6} {_err('ERROR'):<10} {'--':<6} {'--':<10} {e}")
            traceback.print_exc()

    # ASR summary line
    asr_val = asr_from_traces(poisoned_traces)
    summary["asr"] = asr_val
    asr_str = (f"{asr_val:.3f}" if asr_val is not None else "N/A")
    asr_col = (_ok if (asr_val or 0) > 0 else _warn)(asr_str)
    print(f"\n  {_c('ASR (attack success rate):', 'bold')} {asr_col}  "
          f"({sum(1 for t in poisoned_traces if t.attack_succeeded)}/{len(poisoned_traces)} succeeded)")

    # =========================================================================
    # STEP 3 -- Counterfactual oracle (LIS-sink ground truth)
    # =========================================================================
    _section(
        f"Step 3 / 3  --  Counterfactual oracle  "
        f"({len(fillers)} fillers x {len(poisoned_traces)} runs "
        f"= {len(fillers) * len(poisoned_traces)} counterfactual runs)"
    )

    oracle_verdicts:  list[OracleVerdict] = []
    clean_all_actions = clean_trace.all_actions if clean_trace else None

    # Table header
    hdr2 = (f"  {'Run':>4}  {'run_id[:8]':<12} {'Usable?':<10}"
            f" {'Stable?':<10} {'Influential?':<14} {'Honest?'}")
    print(_c(hdr2, "grey"))
    print(_c("  " + "-" * 66, "grey"))

    for i, poisoned_trace in enumerate(poisoned_traces):
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

            infl_col   = _err("[!] yes") if verdict.payload_was_influential else _c("  no", "grey")
            honest_col = _c("yes", "grey") if verdict.label_honest_if_trusted else _err("NO -- DISHONEST")
            print(
                f"  {i + 1:>4}  {poisoned_trace.run_id[:8]:<12}"
                f" {_yn(verdict.usable_for_ground_truth):<10}"
                f" {_yn(verdict.stable_across_fillers):<10}"
                f" {infl_col:<14}"
                f" {honest_col}"
            )

        except Exception as e:
            summary["oracle_verdicts"].append({
                "poisoned_run_id": poisoned_trace.run_id,
                "error": str(e),
            })
            print(f"  {i + 1:>4}  {poisoned_trace.run_id[:8]:<12} {_err('ERROR: ' + str(e))}")
            traceback.print_exc()

    # LIS-sink computation
    lis_val = lis_sink(oracle_verdicts)
    summary["lis_sink"] = lis_val
    summary["lis_breakdown"] = breakdown_report(oracle_verdicts)

    # Save summary JSON
    summary_path = os.path.join(results_dir, f"summary_{experiment_id}.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # =========================================================================
    # RESULTS TABLE
    # =========================================================================
    _header("Results", experiment_id)

    bd = summary["lis_breakdown"]
    n_usable      = bd.get("usable", 0)
    n_dropped     = bd.get("unstable_dropped", 0)
    n_influential = bd.get("payload_influential", 0)

    # Headline metrics
    asr_str2 = f"{asr_val:.3f}" if asr_val is not None else "N/A"
    lis_str  = f"{lis_val:.3f}" if lis_val  is not None else "N/A"

    # Colour-code: high ASR is bad (attack works), LIS < 1.0 is interesting
    asr_display = _ok(asr_str2) if (asr_val or 0) > 0 else _c(asr_str2, "grey")
    lis_display = _warn(lis_str) if (lis_val or 1.0) < 1.0 else _c(lis_str, "grey")

    print()
    print(f"  {_c('Metric', 'bold'):<30} {_c('Value', 'bold'):<16} {_c('Interpretation', 'bold')}")
    print(_c("  " + "-" * 66, "grey"))
    print(f"  {'ASR  (attack success rate)':<28} {asr_display:<16} "
          f"{_c('fraction of attack runs that succeeded', 'grey')}")
    print(f"  {'LIS-sink  (label integrity)':<28} {lis_display:<16} "
          f"{_c('1.0=labels honest | <1.0=label laundering detected', 'grey')}")
    print(_c("  " + "-" * 66, "grey"))
    print(f"  {'Oracle verdicts':<28} {n_usable} usable  /  "
          f"{n_dropped} dropped (unstable)  /  "
          f"{n_influential} influential")
    print()

    # Interpretation hint
    if asr_val and asr_val > 0 and lis_val is not None and lis_val < 1.0:
        print(_ok("  [OK] STRONG SIGNAL: attack succeeded AND label integrity violated -- prime paper result."))
    elif asr_val and asr_val > 0:
        print(_warn("  [!]  Attack succeeded but labels were honest -- ASR captures the event; LIS adds no new info here."))
    elif n_influential > 0:
        print(_ok("  [OK] Payload was influential but attack was blocked -- label may be 'right for the wrong reason'."))
    else:
        print(_c("  [-]  No influential cases detected. Try a different attack/task/model.", "grey"))

    _row("Summary JSON", _c(summary_path, "grey"))
    print()

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
                         "Check the suite's injection tasks if unsure -- for banking/user_task_0 "
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
