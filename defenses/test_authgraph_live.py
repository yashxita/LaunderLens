"""
test_authgraph_live.py  —  Phase 3 Step B: the first LIVE AuthGraph run.

Plain-English idea
------------------
So far AuthGraph has only run with a fake (mock) brain. This script plugs in the
REAL qwen model as AuthGraph's Planner and Checker, and runs it over a CLEAN
banking trace (a legitimate bill payment, no attack).

We are checking one thing: does AuthGraph, driven by a real model, behave sanely?
  - Does the Planner produce a real authorization plan (expected tools + param policies)?
  - Does it ALLOW the legitimate payment (rather than blocking everything or crashing)?

If yes -> the reimplementation is faithful enough to trust for the real experiments.
If it blocks the clean payment -> the Planner/Checker output needs tuning (expected;
this is the fix-on-first-run step).

Run (from repo root, Ollama serving, env set):
    export OPENAI_API_KEY="ollama"
    export LOCAL_LLM_PORT=11434
    python defenses/test_authgraph_live.py --clean-trace logs/<a-clean-run>.json
"""

from __future__ import annotations

import os
import sys
import argparse
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "pipeline"), os.path.join(_ROOT, "defenses"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from trace import Trace
from authgraph import AuthGraph
from apply_defense import apply_defense_to_trace, make_local_llm, defense_blocked_attack


def banking_tool_catalog() -> list[dict]:
    """Pull the banking suite's tools as [{name, description, params}] for the Planner."""
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean-trace", required=True,
                    help="path to a CLEAN (no-attack) banking trace JSON from logs/")
    ap.add_argument("--model-id", default="qwen2.5:14b")
    ap.add_argument("--use-ground-truth-plan", action="store_true",
                    help="use the known-correct authorization plan instead of the LLM "
                         "Planner (isolates the same-observation pollution vulnerability "
                         "from Planner variability)")
    args = ap.parse_args()

    print("Loading clean trace:", args.clean_trace)
    trace = Trace.load(args.clean_trace)
    print(f"  user_task={trace.config.user_task_id}  attack={trace.config.attack}")
    print(f"  actions in this trace: {[a.get('tool') for a in trace.all_actions]}")
    print()

    catalog = banking_tool_catalog()
    print(f"Tool catalog: {[t['name'] for t in catalog]}")
    print()

    print("Building AuthGraph with the REAL qwen model as Planner + Checker...")
    llm = make_local_llm(model_id=args.model_id)
    ag = AuthGraph(llm=llm)

    user_prompt = next((h.output_text for h in trace.hops if h.agent_role == "user"), "")

    suite_name = trace.config.suite or "banking"
    task_id = trace.config.user_task_id or "user_task_0"

    if args.use_ground_truth_plan:
        print("Using GROUND-TRUTH authorization plan (bypassing LLM Planner)...")
        found = ag.use_ground_truth_plan(suite_name, task_id)
        if not found:
            print("ERROR: no ground-truth plan for this suite/task. Falling back to LLM Planner.")
            print("Planner is generating the authorization graph (may take ~30s)...")
            ag.setup(user_prompt, catalog)
    else:
        print("Planner is generating the authorization graph (may take ~30s)...")
        ag.setup(user_prompt, catalog)

    print()
    print("=== AUTHORIZATION PLAN (what is being used) ===")
    if not ag.steps:
        print("  !! No steps — Planner's JSON likely failed to parse.")
    for s in ag.steps:
        print(f"  step {s.step_index}: expect '{s.expected_tool}'  "
              f"policies={json.dumps(s.param_policies)}")
    print(f"  authorized tool set: {sorted(ag.authorized_tools)}")
    print()

    print("=== REPLAYING THE CLEAN TRACE THROUGH AUTHGRAPH (live Checker) ===")
    apply_defense_to_trace(trace, ag, tool_catalog=catalog)
    for d in trace.defense_decisions:
        print(f"  action {d['action_index']}: {d['tool']:22s} "
              f"allow={str(d['allow']):5s} label={d['trust_label']} "
              f"screener={d['screener_decision']} layer={d['layer']}")
    print()

    blocked = defense_blocked_attack(trace)
    print("=== FIDELITY VERDICT ===")
    if not blocked:
        print("  PASS (provisional): AuthGraph ALLOWED the clean legitimate run.")
        print("  This is the expected behaviour on a clean trace — good sign.")
    else:
        print("  ATTENTION: AuthGraph BLOCKED something in a CLEAN run (possible false positive).")
        print("  Check which action + reason above. The Planner's param policy may be too strict,")
        print("  or the clean IBAN wasn't matched. This is tuning, not necessarily a bug.")
    print()
    print("Next: run the SAME on a POISONED trace (Step C) and cross-reference labels vs the oracle.")


if __name__ == "__main__":
    main()