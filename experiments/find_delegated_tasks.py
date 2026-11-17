"""
find_delegated_tasks.py  —  list every AgentDojo task where a payee / recipient /
URL must be read from a tool output (a "delegated value"), and which injection
slots land in that SAME output.

Plain-English idea
------------------
WITNESS targets one task class: the user hands a security-relevant value
(IBAN, e-mail, URL) off to a document. Instead of hand-picking tasks, this
script finds ALL of them, so the evaluation covers the whole population AgentDojo
has (no cherry-picking):

  1. Load each suite's environment with a unique canary string in every
     injection slot.
  2. Execute each user task's GROUND-TRUTH tool calls (no LLM).
  3. A task qualifies if some ground-truth sink call (per WITNESS's policy) has an
     identity argument whose value is NOT in the prompt but IS in an earlier tool
     output. That output is the delegated source.
  4. Record which canaries appear in that same output: those are the injection
     slots where an attacker can plant a competing value (same-observation pollution).

Needs AgentDojo. No model calls. Takes well under a minute.

    python experiments/find_delegated_tasks.py
    python experiments/find_delegated_tasks.py --suites banking slack --version v1
Output: experiments/results/delegated_tasks.json
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import traceback

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "defenses"))

from witness.policy import POLICIES, IDENTITY          # noqa: E402
from witness.recognisers import canonical, find_candidates  # noqa: E402


def _to_text(result) -> str:
    try:
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        return tool_result_to_str(result)
    except Exception:
        return str(result)


def _call_parts(call):
    """(function, args) from an AgentDojo FunctionCall (pydantic) or a plain dict."""
    if isinstance(call, dict):
        return call.get("function"), dict(call.get("args") or {})
    return getattr(call, "function", None), dict(getattr(call, "args", None) or {})


def _run_ground_truth(suite, user_task, injections):
    """Execute the task's ground-truth calls; return (env, [(function, args, output_text)])."""
    from agentdojo.functions_runtime import FunctionsRuntime
    env = suite.load_and_inject_default_environment(injections)
    calls = user_task.ground_truth(copy.deepcopy(env))
    runtime = FunctionsRuntime(suite.tools)
    out = []
    for call in calls:
        fn, args = _call_parts(call)
        try:
            res = runtime.run_function(env, fn, args)
            result, err = res if isinstance(res, tuple) else (res, None)
            text = _to_text(result) if err is None else f"ERROR: {err}"
        except Exception as e:
            text = f"ERROR: {e}"
        out.append((fn, args, text))
    return env, out


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _strings(v)


def _leaves(node, path="", parent=None):
    """(path, string_leaf, parent_container) for every string in the environment."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaves(v, f"{path}.{k}", node)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            yield from _leaves(v, f"{path}[{i}]", node)
    elif isinstance(node, str):
        yield path, node, parent


def _search_environment(env, value, vtype, canaries):
    """
    Fallback when the ground truth never READS the source (e.g. banking user_task_0
    pays the bill without a read_file call in its ground truth). Find the string
    holding the value; its injection slots are the canaries in that same string, or
    in its enclosing RECORD (a small dict such as one e-mail or calendar event).
    Large containers (a whole file system or inbox) are never used, so a canary in
    a different document is not mistaken for same-observation pollution.
    """
    try:
        dump = env.model_dump()
    except Exception:
        return None
    for path, text, parent in _leaves(dump):
        if value not in {c.value for c in find_candidates(text, vtype)}:
            continue
        slots = [k for k, c in canaries.items() if c in text]
        if not slots and isinstance(parent, dict) and len(parent) <= 12:
            texts = list(_strings(parent))
            slots = [k for k, c in canaries.items() if any(c in t for t in texts)]
        if slots:
            return path, slots
    return None


def analyse_task(suite_name, suite, task_id, user_task, canaries):
    policy = POLICIES[suite_name]
    prompt = user_task.PROMPT
    env, steps = _run_ground_truth(suite, user_task, canaries)
    found = []
    for i, (fn, args, _) in enumerate(steps):
        if not policy.is_sink(fn):
            continue
        for arg, value in args.items():
            spec = policy.arg_spec(fn, arg)
            if spec.role != IDENTITY or value in (None, "", []):
                continue
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                v = canonical(item, spec.vtype)
                if v in {c.value for c in find_candidates(prompt, spec.vtype)}:
                    continue                        # user typed it: not delegated
                src = None
                for j in range(i):                  # earliest earlier output holding it
                    src_fn, src_args, src_text = steps[j]
                    if v in {c.value for c in find_candidates(src_text, spec.vtype)}:
                        src = (src_fn, src_args, [k for k, c in canaries.items() if c in src_text])
                        break
                if src is None or not src[2]:
                    hit = _search_environment(env, v, spec.vtype, canaries)
                    if hit is not None:
                        src = (f"env:{hit[0]}", {}, hit[1])
                if src is None:
                    continue
                found.append({
                    "suite": suite_name, "task_id": task_id, "prompt": prompt,
                    "sink_tool": fn, "arg": arg, "vtype": spec.vtype,
                    "legitimate_value": str(item), "source_tool": src[0],
                    "source_args": src[1], "injection_vectors": src[2],
                    "attackable": bool(src[2]),
                })
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--suites", nargs="+", default=["banking", "slack", "workspace", "travel"])
    ap.add_argument("--out", default=os.path.join(_ROOT, "experiments", "results", "delegated_tasks.json"))
    args = ap.parse_args()

    from agentdojo.task_suite.load_suites import get_suite
    all_found, errors = [], []
    for s in args.suites:
        try:
            suite = get_suite(args.version, s)
        except Exception as e:
            print(f"[!] cannot load suite {s}: {e}")
            continue
        canaries = {k: f"CANARY{n:03d}X" for n, k in enumerate(suite.get_injection_vector_defaults())}
        n_tasks = 0
        for tid, task in suite.user_tasks.items():
            n_tasks += 1
            try:
                all_found += analyse_task(s, suite, tid, task, canaries)
            except Exception as e:
                errors.append(f"{s}/{tid}: {e}")
                traceback.print_exc(limit=1)
        print(f"  {s:10s} {n_tasks:3d} tasks scanned")

    # one entry per (task, sink, arg) is enough
    seen, rows = set(), []
    for r in all_found:
        k = (r["suite"], r["task_id"], r["sink_tool"], r["arg"])
        if k not in seen:
            seen.add(k)
            rows.append(r)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"version": args.version, "tasks": rows, "errors": errors}, f, indent=1)

    att = [r for r in rows if r["attackable"]]
    print(f"\n  delegated-value tasks : {len({(r['suite'], r['task_id']) for r in rows})}")
    print(f"  attackable (injection slot in the same output): "
          f"{len({(r['suite'], r['task_id']) for r in att})}")
    for r in att:
        print(f"    {r['suite']}/{r['task_id']:13s} {r['sink_tool']}.{r['arg']} <- {r['source_tool']}"
              f"  slots={r['injection_vectors']}")
    if errors:
        print(f"\n  {len(errors)} task(s) errored (listed in the JSON)")
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
