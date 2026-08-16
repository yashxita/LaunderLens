"""
runner.py  --  the BRIDGE between AgentDojo and your lab notebook (Trace).

Plain-English idea
------------------
AgentDojo can run one agent task, but it only hands back two yes/no results
(did the task succeed? did the attack succeed?) and throws away the step-by-step
story. This file runs one task AND captures that story -- every message the agent
produced -- and writes it all into one Trace JSON file in logs/.

For Phase 1 we run the simplest case: one banking task, no attack, no defence,
using your local Ollama model. When it finishes, one real log file appears.

QUERK FIX -- qwen2.5 inline tool-call format
--------------------------------------------
qwen2.5:14b (via Ollama) sometimes emits tool calls inline in the assistant
message text as:  <function=tool_name>{"arg": "val"}\n```
instead of populating the `tool_calls` array.  _all_actions() detects and
parses both formats, so no runs are silently empty.

Usage (from the LaunderLens repo root, with .venv active and Ollama running):

    set OPENAI_API_KEY=ollama
    set LOCAL_LLM_PORT=11434
    python pipeline/runner.py --suite banking --task user_task_0 --model-id qwen2.5:14b
"""

from __future__ import annotations

import os
import re
import sys
import json
import argparse
import subprocess

# Make `from trace import ...` work no matter where this is run from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# AgentDojo pieces (names verified against the installed package)
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.logging import TraceLogger, OutputLogger
from agentdojo.attacks.attack_registry import load_attack

# our lab notebook (pipeline/trace.py)
from trace import Trace, RunConfig, Hop


# ---------------------------------------------------------------------------
# Terminal output helpers  (keep all runner output consistent)
# ---------------------------------------------------------------------------

COL = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "grey":   "\033[90m",
}


def _c(text: str, *codes: str) -> str:
    """Wrap text in ANSI colour codes."""
    prefix = "".join(COL.get(c, "") for c in codes)
    return f"{prefix}{text}{COL['reset']}"


def _section(title: str) -> None:
    print(f"\n{_c('-' * 62, 'grey')}")
    print(f"  {_c(title, 'bold', 'cyan')}")
    print(_c('-' * 62, 'grey'))


def _git_commit() -> str:
    """Record which exact version of the code produced this run (reproducibility)."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"


def _extract_text(content) -> str:
    """
    Local models (via Ollama) return message content as a LIST of blocks like
    [{'type': 'text', 'content': '...'}], while other models return a plain string.
    This normalises both into clean text so the logs are readable and LIS-friendly.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                # blocks use 'content' or 'text' depending on the model
                parts.append(str(block.get("content", block.get("text", ""))))
            else:
                parts.append(str(block))
        return " ".join(p for p in parts if p)
    return str(content)


# Regex that matches qwen2.5's inline tool-call format:
#   <function=tool_name>{...json...}\n``` (or similar fence endings)
_INLINE_TOOL_RE = re.compile(
    r"<function=([\w.]+)>\s*([\s\S]*?)(?:```|$)",
    re.MULTILINE,
)


def _parse_args(raw) -> dict:
    """
    Parse tool-call arguments that may arrive as:
      * a plain dict (ideal case)
      * a JSON string (some APIs encode args as a string)
      * a JSON string with trailing markdown fences (qwen2.5 quirk:
          '{"file_path": "bill.txt"}\\n```')
    Returns an empty dict on failure rather than crashing.
    """
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {}
    # Strip markdown code fences and surrounding whitespace
    cleaned = re.sub(r"```[a-z]*", "", raw).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {}


def _messages_to_hops(messages) -> list[Hop]:
    """
    Turn AgentDojo's captured message history into our Hop records.

    We record one Hop per message so the whole story is preserved. Trust labels /
    screener fields stay empty here (no defence in Phase 1) -- later phases fill them in.
    """
    hops: list[Hop] = []
    for i, m in enumerate(messages):
        role = m.get("role", "unknown")
        text = _extract_text(m.get("content"))
        hops.append(
            Hop(
                hop_index=i,
                agent_role=role,
                output_text=text[:2000],   # keep logs readable; full text not needed yet
                contains_untrusted_source=(role == "tool"),  # tool output = external data
            )
        )
    return hops


def _all_actions(messages) -> list[dict]:
    """
    Return every tool call the agent made, in order, as clean {"tool","args"} dicts.
    We need the FULL sequence -- not just the last call -- because the security-relevant
    action (e.g. a laundered payment) can happen mid-conversation, with the model doing
    unrelated things afterward (as seen in real traces: it sends the malicious payment,
    then fumbles around confusedly before giving up on the real task).

    Two extraction paths:
      1. Standard: tool_calls array on the message (proper OpenAI format).
      2. Fallback: scan assistant text for qwen2.5's inline <function=name>{...} format
         when tool_calls is absent or empty.  This fixes the all_actions=[] bug where
         the model emits calls as text and the JSON parser (inside AgentDojo) can't
         parse the trailing ``` fence, so the tool_calls array stays empty.
    """
    actions = []
    for m in messages:
        # -- Path 1: standard tool_calls array ------------------------------
        tcs = m.get("tool_calls") or []
        for tc in tcs:
            if isinstance(tc, dict):
                name = tc.get("function") or tc.get("name") or "unknown"
                raw_args = tc.get("args") or tc.get("arguments") or {}
            else:
                name = getattr(tc, "function", getattr(tc, "name", "unknown"))
                raw_args = getattr(tc, "args", getattr(tc, "arguments", {}))
            actions.append({"tool": str(name), "args": _parse_args(raw_args)})

        # -- Path 2: fallback -- inline <function=name>{...} in assistant text --
        # Only used when the tool_calls array is empty; avoids double-counting.
        if not tcs and m.get("role") == "assistant":
            text = _extract_text(m.get("content", ""))
            for match in _INLINE_TOOL_RE.finditer(text):
                tool_name = match.group(1)
                raw_json  = match.group(2).strip()
                parsed    = _parse_args(raw_json)
                if tool_name and (parsed or raw_json):
                    actions.append({"tool": tool_name, "args": parsed})

    return actions


def _final_action(messages) -> dict:
    """
    Return the LAST tool call (kept for backward compatibility / quick summaries).
    For LIS comparisons, prefer _all_actions() -- the harmful action is not always last.
    """
    actions = _all_actions(messages)
    return actions[-1] if actions else {}


def run_one(
    suite_name: str = "banking",
    task_id: str = "user_task_0",
    model: str = "local",
    model_id: str = "llama3.1:8b",
    benchmark_version: str = "v1",
    logs_dir: str = "logs",
    attack_name: str | None = None,
    injection_task_id: str | None = None,
    custom_injections: dict | None = None,
    seed: int = 0,
    temperature: float = 0.0,
) -> str:
    """
    Run ONE user task; save a Trace; return the log path.

    Three modes:
      1. Clean run: attack_name=None, custom_injections=None.
      2. Attack run: attack_name="important_instructions" (etc.) -- the named
         AgentDojo attack generates its own payload text.
      3. Counterfactual run: custom_injections={"injection_bill_text": "<filler text>"}
         -- WE supply the text (e.g. a neutral filler), bypassing the attack object
         entirely. Requires injection_task_id so the environment still sets up the
         same injection slot(s); the attack_name field records "counterfactual" for
         provenance even though no BaseAttack object is used.
    """

    # 1) describe the run (this metadata is what makes it reproducible)
    cfg = RunConfig(
        model=model,
        model_id=model_id,
        seed=seed,
        temperature=temperature,
        suite=suite_name,
        user_task_id=task_id,
        injection_task_id=injection_task_id,
        attack=("counterfactual" if custom_injections is not None else attack_name),
        defense=None,                          # Phase 1/2: no defence yet
        code_commit=_git_commit(),
    )
    trace = Trace(config=cfg)

    # 2) build the agent pipeline (local model, no defence)
    # temperature=0.0 + fixed seed makes runs as deterministic as local models allow.
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=model,
            model_id=model_id,
            defense=None,
            system_message_name=None,
            system_message=None,
            temperature=temperature,
        )
    )

    # 3) load the suite and the specific task
    suite = get_suite(benchmark_version, suite_name)
    user_task = suite.get_user_task_by_id(task_id)

    # 3b) figure out the injections dict for this run
    injection_task = None
    injections: dict = {}

    if custom_injections is not None:
        # Counterfactual mode: use our own text (filler), bypass the attack object.
        if injection_task_id is None:
            injection_task_id = next(iter(suite.injection_tasks.keys()))
            cfg.injection_task_id = injection_task_id
        injection_task = suite.get_injection_task_by_id(injection_task_id)
        injections = custom_injections

    elif attack_name is not None:
        # Attack mode: let the named attack generate its own payload text.
        attacker = load_attack(attack_name, suite, pipeline)
        if injection_task_id is not None:
            injection_task = suite.get_injection_task_by_id(injection_task_id)
        else:
            injection_task_id = next(iter(suite.injection_tasks.keys()))
            injection_task = suite.get_injection_task_by_id(injection_task_id)
            cfg.injection_task_id = injection_task_id
        injections = attacker.attack(user_task, injection_task)

    # 4) run the task INSIDE the logger so we capture the message history.
    #    The pipeline finds this logger via a global stack and calls logger.log(messages),
    #    which populates logger.messages. TraceLogger needs a delegate that has a `logdir`
    #    attribute; OutputLogger(logdir=None) provides one without writing files.
    with TraceLogger(
        delegate=OutputLogger(logdir=None),
        suite_name=suite_name,
        user_task_id=task_id,
        injection_task_id=injection_task_id,
        injections=injections,
        attack_type=attack_name,
        pipeline_name=model_id.replace(":", "_"),
    ) as logger:
        utility, security = suite.run_task_with_pipeline(
            agent_pipeline=pipeline,
            user_task=user_task,
            injection_task=injection_task,
            injections=injections,
        )
        messages = getattr(logger, "messages", [])

    # 5) fill in the trace from what we captured
    trace.hops = _messages_to_hops(messages)
    all_actions = _all_actions(messages)
    trace.all_actions = all_actions
    trace.final_action = all_actions[-1] if all_actions else {}
    trace.attack_succeeded = bool(security)
    trace.notes = (
        f"utility={utility} security={security} "
        f"(attack={attack_name or 'none'}, injection_task={injection_task_id or 'none'})"
    )

    # 6) save one JSON log
    path = trace.save(logs_dir=logs_dir)

    # -- Structured run summary ---------------------------------------------
    utility_str  = _c("[+] completed", "green")  if utility  else _c("[x] incomplete", "red")
    security_str = _c("[+] succeeded", "red")    if security else _c("[x] blocked",    "green")
    actions_str  = str(len(all_actions)) if all_actions else _c("0  [!] none captured", "yellow")

    print(f"\n  {'Task completed':<20} {utility_str}")
    print(f"  {'Attack outcome':<20} {security_str}")
    print(f"  {'Hops captured':<20} {len(trace.hops)}")
    print(f"  {'Actions captured':<20} {actions_str}")
    if all_actions:
        print(f"  {'Final action':<20} {_c(all_actions[-1].get('tool', '?'), 'bold')}  "
              f"{all_actions[-1].get('args', {})}")
    print(f"  {'Log':<20} {_c(path, 'grey')}")

    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run one AgentDojo task and record a Trace.")
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--task", default="user_task_0")
    ap.add_argument("--model", default="local")
    ap.add_argument("--model-id", default="llama3.1:8b")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--attack", default=None,
                     help="AgentDojo attack name, e.g. important_instructions (omit for a clean run)")
    ap.add_argument("--injection-task", default=None,
                     help="Which injection task to target (default: suite's first one)")
    ap.add_argument("--seed", type=int, default=0,
                     help="RNG seed for reproducibility (default: 0)")
    ap.add_argument("--temperature", type=float, default=0.0,
                     help="Sampling temperature (default: 0.0 for deterministic)")
    args = ap.parse_args()

    run_one(
        suite_name=args.suite,
        task_id=args.task,
        model=args.model,
        model_id=args.model_id,
        logs_dir=args.logs_dir,
        attack_name=args.attack,
        injection_task_id=args.injection_task,
        seed=args.seed,
        temperature=args.temperature,
    )