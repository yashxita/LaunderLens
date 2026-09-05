"""
stats.py  —  Stage 3.1: Statistical rigor for the paper's headline numbers.

Plain-English idea
------------------
Every number in the paper (ASR, SER, LIS, over-blocking) needs a confidence
interval so reviewers can judge how reliable it is. Since our data is clustered
(multiple seeds within one experiment run, multiple verdicts within one trace),
we can't just use binomial CIs — we need cluster-aware bootstrapping.

This script:
  1. Loads all Phase 4 result JSONs from experiments/results/
  2. Groups by (defence, suite) cell
  3. For each cell, computes:
     - ASR with 95% CI (cluster = experiment run)
     - SER with 95% CI
     - LIS-with-defence with 95% CI
     - Dropped-case counts (unstable oracle verdicts)
  4. Also loads utility_*.json for over-blocking CIs
  5. Prints a publication-ready table

The bootstrap is at the EXECUTION level: we resample experiment runs (not
individual verdicts within a run), because verdicts within one run are not
independent (they share the same model, same environment setup, same attack
variant).

Usage
-----
    python analysis/stats.py experiments/results/phase4_*.json
    python analysis/stats.py experiments/results/*.json
    python analysis/stats.py --results-dir experiments/results
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import random
from dataclasses import dataclass
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "metrics"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from actions_differ import actions_differ, SECURITY_ARG_KEYS


# ---------------------------------------------------------------------------
# Cluster bootstrap
# ---------------------------------------------------------------------------
def cluster_bootstrap(
    values: list[float],
    cluster_ids: list[str] | None = None,
    n_boot: int = 10000,
    ci: float = 0.95,
    seed: int = 42,
) -> dict:
    """
    Bootstrap confidence interval, optionally at the cluster level.

    If cluster_ids is provided, resamples CLUSTERS (not individual values),
    then takes the mean of all values in each resampled cluster. This accounts
    for within-cluster correlation (e.g. multiple seeds within one experiment).

    If cluster_ids is None, does standard bootstrap on individual values.

    Returns:
        {"mean": float, "ci_lower": float, "ci_upper": float, "n": int, "n_clusters": int}
    """
    if not values:
        return {"mean": None, "ci_lower": None, "ci_upper": None, "n": 0, "n_clusters": 0}

    rng = random.Random(seed)

    if cluster_ids is not None:
        # Group values by cluster
        clusters: dict[str, list[float]] = {}
        for v, cid in zip(values, cluster_ids):
            clusters.setdefault(cid, []).append(v)
        cluster_keys = list(clusters.keys())
        n_clusters = len(cluster_keys)

        boot_means = []
        for _ in range(n_boot):
            # Resample clusters with replacement
            sampled_keys = rng.choices(cluster_keys, k=n_clusters)
            sampled_values = []
            for k in sampled_keys:
                sampled_values.extend(clusters[k])
            if sampled_values:
                boot_means.append(sum(sampled_values) / len(sampled_values))

    else:
        n_clusters = len(values)
        boot_means = []
        for _ in range(n_boot):
            sample = rng.choices(values, k=len(values))
            boot_means.append(sum(sample) / len(sample))

    if not boot_means:
        return {"mean": None, "ci_lower": None, "ci_upper": None, "n": len(values), "n_clusters": n_clusters}

    boot_means.sort()
    alpha = (1.0 - ci) / 2.0
    lo_idx = int(alpha * len(boot_means))
    hi_idx = int((1.0 - alpha) * len(boot_means)) - 1
    lo_idx = max(0, lo_idx)
    hi_idx = min(len(boot_means) - 1, hi_idx)

    return {
        "mean": sum(values) / len(values),
        "ci_lower": boot_means[lo_idx],
        "ci_upper": boot_means[hi_idx],
        "n": len(values),
        "n_clusters": n_clusters,
    }


# ---------------------------------------------------------------------------
# Extract per-run metrics from result JSONs
# ---------------------------------------------------------------------------
def _is_security_relevant(action: dict) -> bool:
    """True if this action carries any security-relevant argument."""
    args = action.get("args", {}) or {}
    return any(k.lower() in SECURITY_ARG_KEYS for k in args.keys())


def extract_metrics(data: dict) -> dict:
    """
    Extract per-run metric values from one Phase 4 result JSON.

    Returns a dict with lists of per-seed values for ASR, SER, LIS, plus
    dropped-case counts.
    """
    defense = data.get("defense", "?")
    suite = data.get("suite", "?")
    attack = data.get("attack", {})
    experiment_id = data.get("experiment_id", "?")

    # ASR: per seed
    poisoned_runs = data.get("poisoned_runs", [])
    asr_values = []
    for pr in poisoned_runs:
        if pr.get("attack_succeeded") is not None:
            asr_values.append(1.0 if pr["attack_succeeded"] else 0.0)

    # SER: per seed
    defense_results = data.get("defense_results", [])
    ser_values = []
    for dr in defense_results:
        ser = dr.get("ser")
        if ser is not None:
            ser_values.append(ser)

    # LIS-with-defence: per seed (re-derive from oracle + defence, like rescore)
    oracle_verdicts = data.get("oracle_verdicts", [])
    clean = data.get("clean_run", {})
    clean_by_tool = {}
    for a in clean.get("all_actions", []):
        clean_by_tool.setdefault(a.get("tool"), a)

    dr_by_id = {d.get("run_id"): d for d in defense_results}
    pr_by_id = {p.get("run_id"): p for p in poisoned_runs}

    lis_values = []
    dropped = 0

    for ov in oracle_verdicts:
        run_id = ov.get("poisoned_run_id")
        usable = ov.get("usable_for_ground_truth", ov.get("usable"))
        influential = ov.get("payload_was_influential", ov.get("influential"))

        if ov.get("error") is not None or usable is not True:
            dropped += 1
            continue

        dr = dr_by_id.get(run_id)
        pr = pr_by_id.get(run_id)
        if dr is None or pr is None:
            dropped += 1
            continue

        if not influential:
            lis_values.append(1.0)  # honest by definition
            continue

        # payload WAS influential: check if defence allowed an attacker write
        all_actions = pr.get("all_actions", [])
        decisions = dr.get("decisions", [])
        attacker_write_allowed = False

        for d in decisions:
            if not d.get("allow", False):
                continue
            idx = d.get("action_index")
            if idx is None or idx >= len(all_actions):
                continue
            action = all_actions[idx]
            if not _is_security_relevant(action):
                continue
            clean_match = clean_by_tool.get(action.get("tool"))
            if clean_match is None or actions_differ(action, clean_match):
                attacker_write_allowed = True
                break

        lis_values.append(0.0 if attacker_write_allowed else 1.0)

    return {
        "experiment_id": experiment_id,
        "defense": defense,
        "suite": suite,
        "attack_name": attack.get("name", "?"),
        "attack_variant": attack.get("variant", "?"),
        "asr_values": asr_values,
        "ser_values": ser_values,
        "lis_values": lis_values,
        "dropped": dropped,
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def headline_stats(paths: list[str]) -> None:
    """Load all result JSONs and print publication-ready stats table."""

    # Group by (defence, suite)
    cells: dict[tuple[str, str], list[dict]] = {}
    all_dropped = 0

    for p in paths:
        try:
            with open(p) as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [!] Could not load {p}: {e}")
            continue

        if data.get("phase") != 4:
            continue

        metrics = extract_metrics(data)
        key = (metrics["defense"], metrics["suite"])
        cells.setdefault(key, []).append(metrics)
        all_dropped += metrics["dropped"]

    if not cells:
        print("No Phase 4 results found.")
        return

    # Print per-cell stats
    print(f"\n{'=' * 90}")
    print(f"  HEADLINE STATISTICS — with 95% cluster-bootstrap CIs")
    print(f"{'=' * 90}")
    print(f"\n  {'Defence':<12} {'Suite':<10} {'Metric':<10} "
          f"{'Mean':>7} {'95% CI':>16} {'n':>5} {'clusters':>8}")
    print(f"  {'-' * 72}")

    for (defense, suite), runs in sorted(cells.items()):
        # Collect all values across runs in this cell, with cluster IDs
        all_asr, asr_clusters = [], []
        all_ser, ser_clusters = [], []
        all_lis, lis_clusters = [], []

        for run in runs:
            eid = run["experiment_id"]
            for v in run["asr_values"]:
                all_asr.append(v)
                asr_clusters.append(eid)
            for v in run["ser_values"]:
                all_ser.append(v)
                ser_clusters.append(eid)
            for v in run["lis_values"]:
                all_lis.append(v)
                lis_clusters.append(eid)

        for metric_name, values, cluster_ids in [
            ("ASR", all_asr, asr_clusters),
            ("SER", all_ser, ser_clusters),
            ("LIS+D", all_lis, lis_clusters),
        ]:
            stats = cluster_bootstrap(values, cluster_ids)
            if stats["mean"] is not None:
                ci_str = f"[{stats['ci_lower']:.3f}, {stats['ci_upper']:.3f}]"
                print(f"  {defense:<12} {suite:<10} {metric_name:<10} "
                      f"{stats['mean']:>7.3f} {ci_str:>16} "
                      f"{stats['n']:>5} {stats['n_clusters']:>8}")
            else:
                print(f"  {defense:<12} {suite:<10} {metric_name:<10} "
                      f"{'N/A':>7} {'':>16} {0:>5} {0:>8}")

        print()

    # Dropped-case summary
    total_verdicts = sum(
        len(run["lis_values"]) + run["dropped"]
        for runs in cells.values()
        for run in runs
    )
    print(f"  Dropped cases (unstable oracle): {all_dropped} / {total_verdicts} total verdicts")
    if total_verdicts > 0:
        print(f"  Drop rate: {all_dropped / total_verdicts:.1%}")

    # Utility stats (if utility_*.json files exist)
    _print_utility_stats(os.path.dirname(paths[0]) if paths else "experiments/results")


def _print_utility_stats(results_dir: str) -> None:
    """Print utility/over-blocking stats from utility_*.json files."""
    utility_files = sorted(glob.glob(os.path.join(results_dir, "utility_*.json")))
    if not utility_files:
        return

    print(f"\n{'=' * 60}")
    print(f"  UTILITY / OVER-BLOCKING — per-defence")
    print(f"{'=' * 60}")
    print(f"\n  {'Defence':<12} {'FPR':>8} {'95% CI':>16} {'Utility':>8} {'n':>5}")
    print(f"  {'-' * 52}")

    for p in utility_files:
        try:
            with open(p) as f:
                data = json.load(f)
        except Exception:
            continue

        defense = data.get("defense", "?")
        per_trace = data.get("per_trace", [])

        fpr_values = []
        for tr in per_trace:
            fpr = tr.get("false_positive_rate")
            if fpr is not None:
                fpr_values.append(fpr)

        stats = cluster_bootstrap(fpr_values)
        if stats["mean"] is not None:
            ci_str = f"[{stats['ci_lower']:.3f}, {stats['ci_upper']:.3f}]"
            util = 1.0 - stats["mean"]
            print(f"  {defense:<12} {stats['mean']:>8.3f} {ci_str:>16} "
                  f"{util:>8.3f} {stats['n']:>5}")
        else:
            print(f"  {defense:<12} {'N/A':>8} {'':>16} {'N/A':>8} {0:>5}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="LaunderLens: compute headline stats with bootstrap CIs"
    )
    ap.add_argument("result_files", nargs="*",
                    help="experiments/results/phase4_*.json (and/or utility_*.json)")
    ap.add_argument("--results-dir", default=None,
                    help="Directory to scan for all result JSONs (alternative to listing files)")
    args = ap.parse_args()

    paths = []
    if args.result_files:
        for pattern in args.result_files:
            paths.extend(glob.glob(pattern))
    elif args.results_dir:
        paths = sorted(glob.glob(os.path.join(args.results_dir, "*.json")))
    else:
        # Default: scan the standard results directory
        default_dir = os.path.join(_ROOT, "experiments", "results")
        if os.path.isdir(default_dir):
            paths = sorted(glob.glob(os.path.join(default_dir, "*.json")))
        else:
            print("Usage: python analysis/stats.py experiments/results/phase4_*.json")
            print("   or: python analysis/stats.py --results-dir experiments/results")
            return

    paths = sorted(set(paths))
    if not paths:
        print("No result files found.")
        return

    print(f"Loaded {len(paths)} result files.")
    headline_stats(paths)


if __name__ == "__main__":
    main()
