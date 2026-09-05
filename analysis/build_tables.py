"""
build_tables.py  —  Stage 5.1: auto-generate every results table from
experiments/results/*.json. No hand-typed numbers anywhere, ever.

Generates:
  - Table 1: Full Attack × Defence matrix (ASR, SER, LIS-sink, LIS+D)
  - Table 2: Utility / over-blocking rates per defence
  - Table 3: Cross-domain consistency (banking vs slack)
  - Table 4: Oracle reliability (κ, n, agreement %)

Outputs to paper/tables/ as .tex (LaTeX) and .md (markdown) files.

Usage
-----
    python analysis/build_tables.py
    python analysis/build_tables.py --results-dir experiments/results
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "metrics"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from actions_differ import actions_differ, SECURITY_ARG_KEYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fmt(val, fmt=".3f"):
    """Format a number or return 'N/A' for None."""
    if val is None:
        return "N/A"
    return f"{val:{fmt}}"


def _is_security_relevant(action: dict) -> bool:
    args = action.get("args", {}) or {}
    return any(k.lower() in SECURITY_ARG_KEYS for k in args.keys())


def _rescore_lis(data: dict) -> tuple[int, int, int]:
    """Re-derive dishonest/honest/skipped counts from a Phase 4 result JSON."""
    clean = data.get("clean_run", {})
    clean_by_tool = {}
    for a in clean.get("all_actions", []):
        clean_by_tool.setdefault(a.get("tool"), a)

    oracle_verdicts = data.get("oracle_verdicts", [])
    defense_results = data.get("defense_results", [])
    poisoned_runs = data.get("poisoned_runs", [])

    dr_by_id = {d.get("run_id"): d for d in defense_results}
    pr_by_id = {p.get("run_id"): p for p in poisoned_runs}

    dishonest, honest, skipped = 0, 0, 0

    for ov in oracle_verdicts:
        run_id = ov.get("poisoned_run_id")
        usable = ov.get("usable_for_ground_truth", ov.get("usable"))
        influential = ov.get("payload_was_influential", ov.get("influential"))

        if ov.get("error") is not None or usable is not True:
            skipped += 1
            continue

        dr = dr_by_id.get(run_id)
        pr = pr_by_id.get(run_id)
        if dr is None or pr is None:
            skipped += 1
            continue

        if not influential:
            honest += 1
            continue

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

        if attacker_write_allowed:
            dishonest += 1
        else:
            honest += 1

    return dishonest, honest, skipped


# ---------------------------------------------------------------------------
# Load and group data
# ---------------------------------------------------------------------------
def load_phase4_results(results_dir: str) -> list[dict]:
    """Load all phase4_*.json files, keeping only the latest per cell."""
    paths = sorted(glob.glob(os.path.join(results_dir, "phase4_*.json")))
    results = []
    for p in paths:
        try:
            with open(p) as f:
                data = json.load(f)
            if data.get("phase") != 4:
                continue
            data["_source_path"] = p
            results.append(data)
        except Exception:
            continue
    return results


def _cell_key(data: dict) -> tuple:
    atk = data.get("attack", {})
    return (
        atk.get("name", "?"),
        atk.get("variant", "?"),
        data.get("defense", "?"),
        data.get("suite", "?"),
    )


def deduplicate_latest(results: list[dict]) -> list[dict]:
    """Keep only the latest result per (attack, variant, defence, suite) cell."""
    by_cell: dict[tuple, dict] = {}
    for r in results:
        key = _cell_key(r)
        existing = by_cell.get(key)
        if existing is None or r.get("experiment_id", "") > existing.get("experiment_id", ""):
            by_cell[key] = r
    return list(by_cell.values())


# ---------------------------------------------------------------------------
# Table 1: Full Attack × Defence matrix
# ---------------------------------------------------------------------------
def build_table1(results: list[dict], output_dir: str) -> None:
    """Full Attack × Defence matrix with ASR, SER, LIS-sink, LIS+D."""

    rows = []
    for data in sorted(results, key=_cell_key):
        atk = data.get("attack", {})
        m = data.get("metrics", {})
        dishonest, honest, skipped = _rescore_lis(data)
        total = dishonest + honest
        lis_d = honest / total if total > 0 else None

        rows.append({
            "attack": atk.get("name", "?"),
            "variant": atk.get("variant", "?"),
            "defense": data.get("defense", "?"),
            "suite": data.get("suite", "?"),
            "asr": m.get("asr"),
            "ser": m.get("ser_avg"),
            "lis_sink": m.get("lis_sink"),
            "lis_d": lis_d,
            "dishonest": dishonest,
            "honest": honest,
        })

    # Markdown
    md_path = os.path.join(output_dir, "table1_matrix.md")
    with open(md_path, "w") as f:
        f.write("# Table 1: Attack × Defence Matrix\n\n")
        f.write(f"| Attack | Variant | Defence | Suite | ASR | SER | LIS-sink | LIS+D | Dishonest | Honest |\n")
        f.write(f"|--------|---------|---------|-------|-----|-----|----------|-------|-----------|--------|\n")
        for r in rows:
            f.write(f"| {r['attack']} | {r['variant']} | {r['defense']} | {r['suite']} "
                    f"| {_fmt(r['asr'])} | {_fmt(r['ser'])} | {_fmt(r['lis_sink'])} "
                    f"| {_fmt(r['lis_d'])} | {r['dishonest']} | {r['honest']} |\n")
    print(f"  Wrote {md_path}")

    # LaTeX
    tex_path = os.path.join(output_dir, "table1_matrix.tex")
    with open(tex_path, "w") as f:
        f.write("% Auto-generated by build_tables.py — do not edit by hand\n")
        f.write("\\begin{table}[htbp]\n\\centering\n\\small\n")
        f.write("\\caption{Full Attack × Defence Matrix}\n")
        f.write("\\label{tab:matrix}\n")
        f.write("\\begin{tabular}{llll rrrr rr}\n\\toprule\n")
        f.write("Attack & Variant & Defence & Suite & ASR & SER & LIS & LIS+D & Dis. & Hon. \\\\\n")
        f.write("\\midrule\n")
        for r in rows:
            f.write(f"{r['attack']} & {r['variant']} & {r['defense']} & {r['suite']} & "
                    f"{_fmt(r['asr'])} & {_fmt(r['ser'])} & {_fmt(r['lis_sink'])} & "
                    f"{_fmt(r['lis_d'])} & {r['dishonest']} & {r['honest']} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    print(f"  Wrote {tex_path}")


# ---------------------------------------------------------------------------
# Table 2: Utility / over-blocking rates per defence
# ---------------------------------------------------------------------------
def build_table2(results_dir: str, output_dir: str) -> None:
    """Utility / over-blocking per defence from utility_*.json."""

    utility_files = sorted(glob.glob(os.path.join(results_dir, "utility_*.json")))
    if not utility_files:
        print("  (No utility_*.json files found — skipping Table 2)")
        return

    rows = []
    for p in utility_files:
        try:
            with open(p) as f:
                data = json.load(f)
            rows.append({
                "defense": data.get("defense", "?"),
                "n_traces": data.get("n_traces", 0),
                "sec_relevant": data.get("total_security_relevant", 0),
                "blocked": data.get("total_blocked", 0),
                "allowed": data.get("total_allowed", 0),
                "fpr": data.get("aggregate_fpr"),
                "utility": data.get("aggregate_utility"),
            })
        except Exception:
            continue

    # Markdown
    md_path = os.path.join(output_dir, "table2_utility.md")
    with open(md_path, "w") as f:
        f.write("# Table 2: Utility / Over-Blocking per Defence\n\n")
        f.write("| Defence | Traces | Sec-Relevant | Blocked | Allowed | FPR | Utility |\n")
        f.write("|---------|--------|--------------|---------|---------|-----|--------|\n")
        for r in rows:
            f.write(f"| {r['defense']} | {r['n_traces']} | {r['sec_relevant']} "
                    f"| {r['blocked']} | {r['allowed']} "
                    f"| {_fmt(r['fpr'])} | {_fmt(r['utility'])} |\n")
    print(f"  Wrote {md_path}")

    # LaTeX
    tex_path = os.path.join(output_dir, "table2_utility.tex")
    with open(tex_path, "w") as f:
        f.write("% Auto-generated by build_tables.py — do not edit by hand\n")
        f.write("\\begin{table}[htbp]\n\\centering\n\\small\n")
        f.write("\\caption{Utility / Over-Blocking per Defence}\n")
        f.write("\\label{tab:utility}\n")
        f.write("\\begin{tabular}{l rrrr rr}\n\\toprule\n")
        f.write("Defence & Traces & Sec-Rel. & Blocked & Allowed & FPR & Utility \\\\\n")
        f.write("\\midrule\n")
        for r in rows:
            f.write(f"{r['defense']} & {r['n_traces']} & {r['sec_relevant']} & "
                    f"{r['blocked']} & {r['allowed']} & "
                    f"{_fmt(r['fpr'])} & {_fmt(r['utility'])} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    print(f"  Wrote {tex_path}")


# ---------------------------------------------------------------------------
# Table 3: Cross-domain consistency
# ---------------------------------------------------------------------------
def build_table3(results: list[dict], output_dir: str) -> None:
    """Cross-domain consistency: banking vs slack side by side."""

    # Group by (defence, suite)
    by_def_suite: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for data in results:
        defense = data.get("defense", "?")
        suite = data.get("suite", "?")
        by_def_suite[(defense, suite)].append(data)

    # Aggregate per (defence, suite)
    agg_rows: dict[str, dict[str, dict]] = defaultdict(dict)
    for (defense, suite), runs in by_def_suite.items():
        total_dishonest, total_honest = 0, 0
        asr_vals, ser_vals = [], []
        for data in runs:
            m = data.get("metrics", {})
            if m.get("asr") is not None:
                asr_vals.append(m["asr"])
            if m.get("ser_avg") is not None:
                ser_vals.append(m["ser_avg"])
            d, h, _ = _rescore_lis(data)
            total_dishonest += d
            total_honest += h

        total = total_dishonest + total_honest
        agg_rows[defense][suite] = {
            "asr": sum(asr_vals) / len(asr_vals) if asr_vals else None,
            "ser": sum(ser_vals) / len(ser_vals) if ser_vals else None,
            "lis_d": total_honest / total if total > 0 else None,
            "dishonest": total_dishonest,
            "honest": total_honest,
            "n_runs": len(runs),
        }

    # Markdown
    md_path = os.path.join(output_dir, "table3_cross_domain.md")
    with open(md_path, "w") as f:
        f.write("# Table 3: Cross-Domain Consistency\n\n")
        suites = sorted({s for _, s in by_def_suite.keys()})
        header = "| Defence | " + " | ".join(f"{s} ASR | {s} LIS+D | {s} n" for s in suites) + " |\n"
        sep = "|---------|" + "|".join("---------|" * 3 for _ in suites) + "\n"
        f.write(header)
        f.write(sep)
        for defense in sorted(agg_rows.keys()):
            parts = [f"| {defense} "]
            for suite in suites:
                d = agg_rows[defense].get(suite, {})
                parts.append(f"| {_fmt(d.get('asr'))} | {_fmt(d.get('lis_d'))} | {d.get('n_runs', 0)} ")
            f.write(" ".join(parts) + "|\n")
    print(f"  Wrote {md_path}")

    # LaTeX
    tex_path = os.path.join(output_dir, "table3_cross_domain.tex")
    with open(tex_path, "w") as f:
        f.write("% Auto-generated by build_tables.py — do not edit by hand\n")
        f.write("\\begin{table}[htbp]\n\\centering\n\\small\n")
        f.write("\\caption{Cross-Domain Consistency}\n")
        f.write("\\label{tab:crossdomain}\n")
        n_suites = len(suites)
        col_spec = "l " + " ".join("rrr" for _ in suites)
        f.write(f"\\begin{{tabular}}{{{col_spec}}}\n\\toprule\n")
        f.write("Defence & " + " & ".join(
            f"\\multicolumn{{3}}{{c}}{{{s}}}" for s in suites
        ) + " \\\\\n")
        f.write(" & " + " & ".join("ASR & LIS+D & n" for _ in suites) + " \\\\\n")
        f.write("\\midrule\n")
        for defense in sorted(agg_rows.keys()):
            parts = [defense]
            for suite in suites:
                d = agg_rows[defense].get(suite, {})
                parts.extend([
                    _fmt(d.get("asr")),
                    _fmt(d.get("lis_d")),
                    str(d.get("n_runs", 0)),
                ])
            f.write(" & ".join(parts) + " \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    print(f"  Wrote {tex_path}")


# ---------------------------------------------------------------------------
# Table 4: Oracle reliability
# ---------------------------------------------------------------------------
def build_table4(output_dir: str) -> None:
    """Oracle reliability from kappa_ratings.json."""

    ratings_path = os.path.join(_ROOT, "analysis", "kappa_ratings.json")
    if not os.path.exists(ratings_path):
        print("  (kappa_ratings.json not found — skipping Table 4)")
        return

    with open(ratings_path) as f:
        ratings = json.load(f)

    # We can't compute kappa here without the case metadata (oracle verdicts),
    # but we can report the counts from the ratings file
    total = len(ratings)
    influential = sum(1 for r in ratings.values() if r.get("human_rating") == "influential")
    not_influential = sum(1 for r in ratings.values() if r.get("human_rating") == "not_influential")
    unclear = sum(1 for r in ratings.values() if r.get("human_rating") == "unclear")
    skipped = sum(1 for r in ratings.values() if r.get("human_rating") is None)

    md_path = os.path.join(output_dir, "table4_oracle.md")
    with open(md_path, "w") as f:
        f.write("# Table 4: Oracle Reliability\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Total rated | {total} |\n")
        f.write(f"| Influential | {influential} |\n")
        f.write(f"| Not influential | {not_influential} |\n")
        f.write(f"| Unclear | {unclear} |\n")
        f.write(f"| Skipped | {skipped} |\n")
        f.write(f"| Usable for κ | {influential + not_influential} |\n")
        f.write("\n*Note: Run `python analysis/kappa_rate.py --report-only` for full κ computation.*\n")
    print(f"  Wrote {md_path}")

    # LaTeX
    tex_path = os.path.join(output_dir, "table4_oracle.tex")
    with open(tex_path, "w") as f:
        f.write("% Auto-generated by build_tables.py — do not edit by hand\n")
        f.write("\\begin{table}[htbp]\n\\centering\n\\small\n")
        f.write("\\caption{Oracle Reliability}\n")
        f.write("\\label{tab:oracle}\n")
        f.write("\\begin{tabular}{lr}\n\\toprule\n")
        f.write("Metric & Value \\\\\n\\midrule\n")
        f.write(f"Total rated & {total} \\\\\n")
        f.write(f"Influential & {influential} \\\\\n")
        f.write(f"Not influential & {not_influential} \\\\\n")
        f.write(f"Unclear & {unclear} \\\\\n")
        f.write(f"Usable for $\\kappa$ & {influential + not_influential} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    print(f"  Wrote {tex_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="LaunderLens: auto-generate all results tables from experiment JSONs"
    )
    ap.add_argument("--results-dir", default=os.path.join(_ROOT, "experiments", "results"))
    ap.add_argument("--output-dir", default=os.path.join(_ROOT, "paper", "tables"))
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Results dir: {args.results_dir}")
    print(f"Output dir:  {args.output_dir}")

    # Load Phase 4 results
    results = load_phase4_results(args.results_dir)
    results = deduplicate_latest(results)
    print(f"\nLoaded {len(results)} Phase 4 results (deduplicated to latest per cell).")

    # Build tables
    print("\n--- Table 1: Attack × Defence Matrix ---")
    build_table1(results, args.output_dir)

    print("\n--- Table 2: Utility / Over-Blocking ---")
    build_table2(args.results_dir, args.output_dir)

    print("\n--- Table 3: Cross-Domain Consistency ---")
    build_table3(results, args.output_dir)

    print("\n--- Table 4: Oracle Reliability ---")
    build_table4(args.output_dir)

    print(f"\nDone. All tables written to {args.output_dir}/")


if __name__ == "__main__":
    main()
