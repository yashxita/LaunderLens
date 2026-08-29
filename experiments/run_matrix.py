"""
run_matrix.py  —  Full Attack x Defense x Suite matrix runner.

Automates the complete evaluation grid for the paper:

    Attacks  (3 x 3 variants = 9 variants)
      x Defenses (authgraph, rtbas)
      x Suites   (banking, ...)  [extendable]

Delegates each cell to run_phase4.py's run_one_variant() function.
Every cell writes its own JSON result file to experiments/results/.
After all cells finish, it prints the full matrix table and computes
the literal baseline residual class from the collected logs.

Usage
-----
    # Dry run (print what would run, touch nothing):
    python experiments/run_matrix.py --dry-run

    # Run banking suite, all attacks x both defenses, 3 seeds each:
    python experiments/run_matrix.py --seeds 3

    # Add more suites:
    python experiments/run_matrix.py --suites banking workspace --seeds 3

    # Only specific defenses:
    python experiments/run_matrix.py --defenses authgraph --seeds 3

    # Resume (skip cells whose result JSON already exists):
    python experiments/run_matrix.py --seeds 3 --skip-existing
"""

from __future__ import annotations

import argparse
import datetime
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

# Import everything from the single-variant runner
import copy                                        # noqa: E402
from run_phase4 import run_one_variant            # noqa: E402
from attack_base import DEFAULT_BANKING_CTX, DEFAULT_SLACK_CTX  # noqa: E402
from attribution_forgery import AttributionForgery, ALL_VARIANTS as AF_VARIANTS   # noqa
from label_join import LabelJoin, ALL_VARIANTS as LJ_VARIANTS                     # noqa
from multi_hop_reemission import MultiHopReemission, ALL_VARIANTS as MHR_VARIANTS # noqa
from slack_attacks import SlackInviteRedirect, ALL_VARIANTS as SLACK_VARIANTS     # noqa
from rtbas_attacks import (JudgeHijack, SourceConfusion, RegionSpoof,             # noqa
                           ALL_JUDGE_HIJACK_VARIANTS, ALL_SOURCE_CONFUSION_VARIANTS,  # noqa
                           ALL_REGION_SPOOF_VARIANTS)                              # noqa
from literal_baseline import LiteralBaseline                                      # noqa


# ---------------------------------------------------------------------------
# Matrix dimensions
# ---------------------------------------------------------------------------

# Attacks are suite-specific (they target that suite's own tools), so the
# matrix looks up which attacks apply per-suite rather than applying one
# global attack list to every suite. ALL_ATTACKS is kept as the banking list
# for backward compatibility with anything still importing it directly.
# AuthGraph-targeted attacks (the original 9 variants)
AUTHGRAPH_ATTACKS = (
    [AttributionForgery(variant=v) for v in AF_VARIANTS] +
    [LabelJoin(variant=v)          for v in LJ_VARIANTS] +
    [MultiHopReemission(variant=v) for v in MHR_VARIANTS]
)

# RTBAS-targeted attacks (6 new variants: 3 strategies × 2 each)
RTBAS_ATTACKS = (
    [JudgeHijack(variant=v)     for v in ALL_JUDGE_HIJACK_VARIANTS] +
    [SourceConfusion(variant=v) for v in ALL_SOURCE_CONFUSION_VARIANTS] +
    [RegionSpoof(variant=v)     for v in ALL_REGION_SPOOF_VARIANTS]
)

# ALL_ATTACKS includes everything for the banking suite
ALL_ATTACKS = AUTHGRAPH_ATTACKS + RTBAS_ATTACKS

SUITE_ATTACKS: dict[str, list] = {
    "banking": ALL_ATTACKS,
    "slack":   [SlackInviteRedirect(variant=v) for v in SLACK_VARIANTS],
}

# Base TaskContext (injection_key/injection_task_id/attacker target, etc.) per
# suite — each suite's real environment data differs (confirmed live for slack
# on 2026-08-27/28: injection_key='injection_dora_0', task_id='user_task_2').
SUITE_CTX = {
    "banking": DEFAULT_BANKING_CTX,
    "slack":   DEFAULT_SLACK_CTX,
}

ALL_DEFENSES = ["authgraph", "rtbas"]

# Suites: each entry is (suite_name, task_id).
# Add more rows here as you expand beyond banking.
ALL_SUITES = [
    ("banking", "user_task_0"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cell_id(attack_name: str, variant: str,
             defense: str, suite: str, task: str) -> str:
    return f"{attack_name}__{variant}__{defense}__{suite}__{task}"


def _result_path(results_dir: str, cell_id: str) -> str:
    return os.path.join(results_dir, f"{cell_id}.json")


def _c(text: str, *styles: str) -> str:
    """ANSI colour helper (same as run_phase4.py)."""
    codes = {"bold": "1", "red": "31", "green": "32", "yellow": "33",
             "cyan": "36", "white": "37", "grey": "90"}
    esc = ";".join(codes.get(s, "") for s in styles if s in codes)
    return f"\033[{esc}m{text}\033[0m" if esc else text


def _header(title: str, subtitle: str = "") -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    if subtitle:
        print(f"  {subtitle}")
    print(f"{'=' * 70}")


# ---------------------------------------------------------------------------
# Matrix runner
# ---------------------------------------------------------------------------

def run_matrix(
    defenses: list[str],
    suites: list[tuple[str, str]],
    model_id: str,
    n_seeds: int,
    logs_dir: str,
    results_dir: str,
    dry_run: bool,
    skip_existing: bool,
    use_ground_truth_plan: bool,
) -> list[dict]:
    """
    Run the full Attack x Defense x Suite matrix.
    Returns a list of result dicts (one per cell).
    """
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    # Build full cell list (attacks are suite-specific: each suite only runs
    # the attacks crafted for its own tools — see SUITE_ATTACKS)
    cells = []
    for suite, task in suites:
        suite_attacks = SUITE_ATTACKS.get(suite, [])
        for defense in defenses:
            for attack in suite_attacks:
                cells.append((suite, task, defense, attack))

    n_attack_variants = sum(len(SUITE_ATTACKS.get(s, [])) for s, _ in suites)
    _header(
        "LaunderLens — Full Matrix Run",
        f"{len(cells)} cells  "
        f"({n_attack_variants} attack variant(s) across {len(suites)} suite(s) "
        f"× {len(defenses)} defense(s))"
    )
    print(f"\n  Defenses : {', '.join(defenses)}")
    print(f"  Suites   : {', '.join(f'{s}/{t}' for s, t in suites)}")
    print(f"  Seeds    : {n_seeds}")
    print(f"  Model    : {model_id}")
    if dry_run:
        print(f"\n  {_c('DRY RUN — no model calls will be made', 'yellow')}")

    print(f"\n  {'#':<4} {'Suite':<10} {'Defense':<12} {'Attack':<25} {'Variant':<22}")
    print(f"  {'-' * 76}")
    for i, (suite, task, defense, attack) in enumerate(cells, 1):
        cid = _cell_id(attack.name, attack.variant, defense, suite, task)
        exists = os.path.exists(_result_path(results_dir, cid))
        skip_flag = f"  {_c('[SKIP]', 'grey')}" if (exists and skip_existing) else ""
        print(f"  {i:<4} {suite:<10} {defense:<12} {attack.name:<25} "
              f"{attack.variant:<22}{skip_flag}")

    if dry_run:
        print(f"\n  {_c('Dry-run complete — exiting.', 'yellow')}\n")
        return []

    # ---- Execute ----
    all_results: list[dict] = []
    start_time = datetime.datetime.now()

    for i, (suite, task, defense, attack) in enumerate(cells, 1):
        cid = _cell_id(attack.name, attack.variant, defense, suite, task)
        rpath = _result_path(results_dir, cid)

        if skip_existing and os.path.exists(rpath):
            print(f"\n  [{i}/{len(cells)}] SKIP (result exists): {cid}")
            with open(rpath) as fh:
                all_results.append(json.load(fh))
            continue

        print(f"\n  [{i}/{len(cells)}] "
              f"{_c(attack.name, 'bold')}/{attack.variant}  "
              f"vs  {_c(defense, 'cyan')}  "
              f"on  {suite}/{task}")

        # Never mutate the shared DEFAULT_*_CTX singletons directly — that
        # would corrupt them for later cells in the same process (the same
        # class of bug run_phase4.py's main() already guards against).
        ctx = copy.deepcopy(SUITE_CTX.get(suite, DEFAULT_BANKING_CTX))
        ctx.suite   = suite
        ctx.task_id = task

        try:
            result = run_one_variant(
                attack=attack,
                ctx=ctx,
                model_id=model_id,
                n_seeds=n_seeds,
                use_ground_truth_plan=use_ground_truth_plan,
                logs_dir=logs_dir,
                results_dir=results_dir,
                dry_run=False,
                defense_name=defense,
            )
            all_results.append(result)
        except Exception as exc:
            print(f"\n  {_c('ERROR', 'bold', 'red')} in cell {cid}:")
            traceback.print_exc()
            all_results.append({
                "cell_id": cid,
                "error": str(exc),
                "attack": {"name": attack.name, "variant": attack.variant},
                "defense": defense,
                "suite": suite,
            })

    elapsed = datetime.datetime.now() - start_time
    return all_results


# ---------------------------------------------------------------------------
# Summary table + residual class
# ---------------------------------------------------------------------------

def print_matrix_table(results: list[dict]) -> None:
    """Print the full matrix results table."""
    _header("Full Matrix — Results Table")
    hdr = (f"  {'Attack':<22} {'Variant':<20} {'Defense':<11} "
           f"{'Suite':<9} {'ASR':>6} {'SER':>6} {'LIS':>6} {'LIS+D':>7}")
    print(hdr)
    print(f"  {'-' * 87}")

    for r in results:
        if "error" in r:
            m = {}
            atk_d = r.get("attack", {})
            def_str = r.get("defense", "?")
            suite_str = r.get("suite", "?")
        else:
            m = r.get("metrics", {})
            atk_d = r.get("attack", {})
            def_str = r.get("defense", "?")
            suite_str = r.get("suite", "?")

        asr  = f"{m.get('asr', 0):.3f}"        if m.get("asr")            is not None else "N/A"
        ser  = f"{m.get('ser_avg', 0):.3f}"    if m.get("ser_avg")        is not None else "N/A"
        lis  = f"{m.get('lis_sink', 0):.3f}"   if m.get("lis_sink")       is not None else "N/A"
        lisd = f"{m.get('lis_with_defense', 0):.3f}" if m.get("lis_with_defense") is not None else "N/A"

        if "error" in r:
            asr = ser = lis = lisd = _c("ERR", "red")

        print(f"  {atk_d.get('name', '?'):<22} {atk_d.get('variant', '?'):<20} "
              f"{def_str:<11} {suite_str:<9} "
              f"{asr:>6} {ser:>6} {lis:>6} {lisd:>7}")


def print_residual_class(logs_dir: str) -> None:
    """Run the literal baseline over all collected logs and print residual summary."""
    import glob as _glob
    log_files = sorted(_glob.glob(os.path.join(logs_dir, "**", "*.json"), recursive=True))
    if not log_files:
        print("\n  (No log files found for literal baseline — run matrix first.)")
        return

    _header("Literal Baseline — Residual Class")
    lb = LiteralBaseline(fuzzy=True)
    verdicts = lb.score_log_files(log_files)
    lb.print_summary(verdicts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="LaunderLens: run full Attack x Defense x Suite matrix"
    )
    ap.add_argument("--defenses", nargs="+",
                    choices=["authgraph", "rtbas"],
                    default=ALL_DEFENSES,
                    help="Which defenses to include (default: all)")
    ap.add_argument("--suites", nargs="+",
                    default=["banking"],
                    help="AgentDojo suites to run (default: banking)")
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--results-dir", default="experiments/results")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Skip cells whose result JSON already exists (resume)")
    ap.add_argument("--use-llm-planner", action="store_true",
                    help="Use LLM Planner instead of ground-truth plan")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would run without executing")
    ap.add_argument("--residual-only", action="store_true",
                    help="Only compute literal baseline on existing logs (no new runs)")
    args = ap.parse_args()

    if args.residual_only:
        print_residual_class(args.logs_dir)
        return

    # Map suite names → (suite, task) pairs
    suite_map = {
        "banking":   ("banking",   "user_task_0"),
        "workspace": ("workspace", "user_task_0"),
        "travel":    ("travel",    "user_task_0"),
        # slack's real task is user_task_2 ("Invite Dora to Slack...") —
        # confirmed against agentdojo's own environment/injection data on
        # 2026-08-27; user_task_0 does not exist for this suite.
        "slack":     ("slack",     DEFAULT_SLACK_CTX.task_id),
    }
    suites = [suite_map.get(s, (s, "user_task_0")) for s in args.suites]

    results = run_matrix(
        defenses=args.defenses,
        suites=suites,
        model_id=args.model_id,
        n_seeds=args.seeds,
        logs_dir=args.logs_dir,
        results_dir=args.results_dir,
        dry_run=args.dry_run,
        skip_existing=args.skip_existing,
        use_ground_truth_plan=not args.use_llm_planner,
    )

    if results and not args.dry_run:
        print_matrix_table(results)
        print_residual_class(args.logs_dir)


if __name__ == "__main__":
    main()
