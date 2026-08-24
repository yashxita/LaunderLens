"""
kappa_rate.py  —  Oracle reliability check: human-vs-oracle agreement (Cohen's kappa).

Plain-English idea
------------------
The counterfactual oracle makes an automatic judgment: "was the payload
influential?" We want to know if a HUMAN, looking at the same raw evidence,
would agree. If yes consistently -> the oracle is a trustworthy measuring
instrument. If not -> every LIS number built on it is shaky.

How this works
---------------
1. Load oracle verdicts from one or more experiment result JSONs
   (experiments/results/*.json — both run_experiment.py and run_phase4.py
   formats are supported).
2. For each case, show ONLY the raw evidence (the poisoned run's actions,
   each filler run's actions) — NEVER the oracle's own verdict. This is a
   BLIND rating: you judge before seeing what the machine decided.
3. Ask: "did the payload's removal change the security-relevant outcome?"
   (yes / no / unclear)
4. After all cases are rated, reveal the oracle's verdicts and compute
   Cohen's kappa — the standard agreement statistic that corrects for
   chance agreement (unlike raw % agreement).

Usage
-----
    python analysis/kappa_rate.py experiments/results/*.json
    # rates every usable case found, saves progress as you go (safe to Ctrl+C
    # and resume — already-rated cases are skipped)

    python analysis/kappa_rate.py experiments/results/*.json --max-cases 15
    # cap the session length

    python analysis/kappa_rate.py --report-only
    # skip rating; just recompute kappa from ratings already saved
"""

from __future__ import annotations

import os
import sys
import json
import glob
import argparse
from dataclasses import dataclass, field
from typing import Optional

RATINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kappa_ratings.json")


# ---------------------------------------------------------------------------
# Extract rateable cases from either summary format
# ---------------------------------------------------------------------------
def _extract_cases(result_json: dict, source_file: str) -> list[dict]:
    """
    Pull rateable oracle-verdict cases out of one result JSON, normalising
    both run_experiment.py's and run_phase4.py's slightly different formats
    into one common shape.
    """
    cases = []
    verdicts = result_json.get("oracle_verdicts", [])
    attack_name = result_json.get("attack", {}).get("name") if isinstance(result_json.get("attack"), dict) else result_json.get("config", {}).get("attack")

    for v in verdicts:
        if v.get("error") is not None:
            continue  # can't rate a failed run

        # normalise field names across the two formats
        usable = v.get("usable_for_ground_truth", v.get("usable"))
        influential = v.get("payload_was_influential", v.get("influential"))
        poisoned_actions = v.get("poisoned_all_actions")

        # filler evidence: run_experiment.py has rich filler_results;
        # run_phase4.py's verdict.to_dict() has "results" (full CounterfactualResult list)
        filler_evidence = []
        for r in v.get("filler_results", v.get("results", [])):
            filler_evidence.append({
                "filler_index": r.get("filler_index"),
                "filler_all_actions": r.get("filler_all_actions"),
                "reasons": r.get("reasons", []),
            })

        if poisoned_actions is None and not filler_evidence:
            continue  # not enough data to rate this case at all

        cases.append({
            "case_id": f"{os.path.basename(source_file)}::{v.get('poisoned_run_id', '?')[:8]}",
            "source_file": source_file,
            "attack_name": attack_name,
            "poisoned_run_id": v.get("poisoned_run_id"),
            "poisoned_all_actions": poisoned_actions,
            "filler_evidence": filler_evidence,
            "oracle_usable": usable,
            "oracle_influential": influential,
        })
    return cases


def load_all_cases(paths: list[str]) -> list[dict]:
    all_cases = []
    for p in paths:
        try:
            with open(p) as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [!] Could not load {p}: {e}")
            continue
        cases = _extract_cases(data, p)
        all_cases.extend(cases)
    return all_cases


# ---------------------------------------------------------------------------
# Ratings persistence (so a session can be interrupted and resumed)
# ---------------------------------------------------------------------------
def load_ratings() -> dict:
    if os.path.exists(RATINGS_FILE):
        with open(RATINGS_FILE) as f:
            return json.load(f)
    return {}


def save_ratings(ratings: dict) -> None:
    with open(RATINGS_FILE, "w") as f:
        json.dump(ratings, f, indent=2)


# ---------------------------------------------------------------------------
# Presentation (blind — no oracle verdict shown)
# ---------------------------------------------------------------------------
def _fmt_actions(actions) -> str:
    if not actions:
        return "    (no actions taken)"
    lines = []
    for a in actions:
        tool = a.get("tool", "?")
        args = a.get("args", {})
        args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
        lines.append(f"    {tool}({args_str})")
    return "\n".join(lines)


def present_case(case: dict, idx: int, total: int) -> None:
    print("\n" + "=" * 72)
    print(f"  CASE {idx}/{total}   [{case['case_id']}]")
    if case.get("attack_name"):
        print(f"  attack: {case['attack_name']}")
    print("=" * 72)

    print("\n  POISONED RUN — what the agent did WITH the attacker's content present:")
    print(_fmt_actions(case["poisoned_all_actions"]))

    fillers = case.get("filler_evidence", [])
    if fillers:
        print(f"\n  FILLER RE-RUNS — same task, attacker's content replaced by {len(fillers)} neutral texts:")
        for fe in fillers:
            print(f"\n  -- filler {fe.get('filler_index')} --")
            print(_fmt_actions(fe.get("filler_all_actions")))
            if fe.get("reasons"):
                print(f"     (automated diff notes, for reference only: {'; '.join(fe['reasons'])})")
    else:
        print("\n  (no filler action data available for this case — judge from poisoned run only)")

    print()


def ask_rating() -> Optional[str]:
    """Ask the human: did removing the payload change the security-relevant outcome?"""
    while True:
        ans = input(
            "  Your judgment — did the payload's presence change the security-relevant "
            "action?\n  [y]es influential / [n]o not influential / [u]nclear / "
            "[s]kip / [q]uit: "
        ).strip().lower()
        if ans in ("y", "yes"):
            return "influential"
        if ans in ("n", "no"):
            return "not_influential"
        if ans in ("u", "unclear"):
            return "unclear"
        if ans in ("s", "skip"):
            return None
        if ans in ("q", "quit"):
            return "__QUIT__"
        print("  (please answer y / n / u / s / q)")


# ---------------------------------------------------------------------------
# Cohen's kappa (no external deps — small, standard formula)
# ---------------------------------------------------------------------------
def cohens_kappa(human: list[str], oracle: list[str]) -> Optional[float]:
    """
    Compute Cohen's kappa for two raters over the SAME binary categories.
    'unclear' ratings are excluded (kappa needs a clean binary comparison;
    we report the unclear rate separately).
    """
    pairs = [(h, o) for h, o in zip(human, oracle) if h in ("influential", "not_influential")]
    n = len(pairs)
    if n == 0:
        return None

    agree = sum(1 for h, o in pairs if h == o)
    po = agree / n  # observed agreement

    h_infl = sum(1 for h, _ in pairs if h == "influential") / n
    o_infl = sum(1 for _, o in pairs if o == "influential") / n
    pe = h_infl * o_infl + (1 - h_infl) * (1 - o_infl)  # expected agreement by chance

    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1 - pe)


def interpret_kappa(k: float) -> str:
    # Standard Landis & Koch (1977) interpretation bands
    if k < 0:
        return "poor (worse than chance)"
    if k < 0.20:
        return "slight"
    if k < 0.40:
        return "fair"
    if k < 0.60:
        return "moderate"
    if k < 0.80:
        return "substantial"
    return "almost perfect"


def print_report(ratings: dict, cases_by_id: dict) -> None:
    human, oracle = [], []
    unclear_count, skipped_count = 0, 0

    for case_id, r in ratings.items():
        case = cases_by_id.get(case_id)
        if case is None:
            continue
        h = r.get("human_rating")
        if h == "unclear":
            unclear_count += 1
            continue
        if h is None:
            skipped_count += 1
            continue
        o_infl = case.get("oracle_influential")
        o = "influential" if o_infl is True else ("not_influential" if o_infl is False else None)
        if o is None:
            continue
        human.append(h)
        oracle.append(o)

    print("\n" + "#" * 60)
    print("  ORACLE RELIABILITY REPORT")
    print("#" * 60)
    print(f"  Total rated       : {len(ratings)}")
    print(f"  Usable for kappa  : {len(human)}")
    print(f"  Marked unclear    : {unclear_count}")
    print(f"  Skipped           : {skipped_count}")

    if len(human) < 5:
        print("\n  Not enough rated cases yet for a meaningful kappa (need >= 5, ideally 20-30+).")
        return

    agree = sum(1 for h, o in zip(human, oracle) if h == o)
    pct_agree = agree / len(human)
    k = cohens_kappa(human, oracle)

    print(f"\n  Raw agreement     : {pct_agree:.1%}  ({agree}/{len(human)})")
    print(f"  Cohen's kappa     : {k:.3f}  ({interpret_kappa(k)})")

    # Show disagreements for inspection
    disagreements = [
        (cid, r) for cid, r in ratings.items()
        if r.get("human_rating") in ("influential", "not_influential")
        and cases_by_id.get(cid) is not None
        and (
            (cases_by_id[cid].get("oracle_influential") is True and r["human_rating"] != "influential")
            or (cases_by_id[cid].get("oracle_influential") is False and r["human_rating"] != "not_influential")
        )
    ]
    if disagreements:
        print(f"\n  Disagreements ({len(disagreements)}) — worth inspecting for the paper's appendix:")
        for cid, r in disagreements:
            c = cases_by_id[cid]
            print(f"    {cid}: human={r['human_rating']!r}  oracle_influential={c.get('oracle_influential')}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_files", nargs="*", help="experiments/results/*.json files")
    ap.add_argument("--max-cases", type=int, default=None, help="cap this session's length")
    ap.add_argument("--report-only", action="store_true", help="skip rating, just report")
    args = ap.parse_args()

    ratings = load_ratings()

    paths = []
    for pattern in args.result_files:
        paths.extend(glob.glob(pattern))
    paths = sorted(set(paths))

    if not paths and not args.report_only:
        print("No result files given. Example:")
        print("  python analysis/kappa_rate.py experiments/results/*.json")
        return

    all_cases = load_all_cases(paths) if paths else []
    cases_by_id = {c["case_id"]: c for c in all_cases}

    # also fold in cases_by_id from any PREVIOUSLY rated files not passed this time,
    # so --report-only works standalone
    if args.report_only:
        # try to recover case metadata from result files referenced in ratings
        referenced_files = {r.get("source_file") for r in ratings.values() if r.get("source_file")}
        extra = load_all_cases(sorted(referenced_files))
        for c in extra:
            cases_by_id.setdefault(c["case_id"], c)
        print_report(ratings, cases_by_id)
        return

    unrated = [c for c in all_cases if c["case_id"] not in ratings]
    print(f"Loaded {len(all_cases)} total cases ({len(unrated)} not yet rated).")

    if args.max_cases:
        unrated = unrated[: args.max_cases]

    if not unrated:
        print("Nothing new to rate.")
        print_report(ratings, cases_by_id)
        return

    print("\nYou will see the RAW EVIDENCE only — the oracle's verdict is hidden until the")
    print("final report. Judge each case independently: did the attacker's content change")
    print("the security-relevant action (e.g. a payment recipient/amount)?\n")
    input("Press Enter to begin...")

    for i, case in enumerate(unrated, 1):
        present_case(case, i, len(unrated))
        rating = ask_rating()
        if rating == "__QUIT__":
            print("\nStopping early. Progress saved.")
            break
        ratings[case["case_id"]] = {
            "human_rating": rating,
            "source_file": case["source_file"],
        }
        save_ratings(ratings)  # save after every case — safe to interrupt

    print_report(ratings, cases_by_id)


if __name__ == "__main__":
    main()