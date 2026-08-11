"""
runner.py  —  the BRIDGE between AgentDojo and your lab notebook (Trace).

Plain-English idea
------------------
AgentDojo can run one agent task, but it only hands back two yes/no results
(did the task succeed? did the attack succeed?) and throws away the step-by-step
story. This file runs one task AND captures that story — every message the agent
produced — and writes it all into one Trace JSON file in logs/.

For Phase 1 we run the simplest case: one banking task, no attack, no defence,
using your local Ollama model. When it finishes, one real log file appears.

Usage (from the LaunderLens repo root, with .venv active and Ollama running):

    export OPENAI_API_KEY="ollama"
    export OPENAI_BASE_URL="http://localhost:11434/v1"
    python pipeline/runner.py --suite banking --task user_task_0 --model-id llama3.1:8b
"""

from __future__ import annotations

import argparse
import subprocess

# AgentDojo pieces (names verified against the installed package)
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.logging import TraceLogger, NullLogger

# our lab notebook
from trace import Trace, RunConfig, Hop


def _git_commit() -> str:
    """Record which exact version of the code produced this run (reproducibility)."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"


def _messages_to_hops(messages) -> list[Hop]:
    """
    Turn AgentDojo's captured message history into our Hop records.

    AgentDojo stores the conversation as a list of message dicts, each with a
    'role' (system / user / assistant / tool) and 'content'. We record one Hop
    per message so the whole story is preserved. Trust labels / screener fields
    stay empty here (no defence in Phase 1) — later phases fill them in.
    """
    hops: list[Hop] = []
    for i, m in enumerate(messages):
        role = m.get("role", "unknown")
        content = m.get("content", "")
        if content is None:
            content = ""
        # a message coming from a 'tool' is external/observation data -> untrusted-ish
        untrusted = role in ("tool", "user")  # user task is trusted; tool output is external
        hops.append(
            Hop(
                hop_index=i,
                agent_role=role,
                output_text=str(content)[:2000],   # keep logs readable; full text not needed yet
                contains_untrusted_source=(role == "tool"),
            )
        )
    return hops


def _final_action(messages) -> dict:
    """
    Find the last tool call the agent made — that's the 'action' it took.
    Returns {} if the agent never called a tool.
    """
    for m in reversed(messages):
        tcs = m.get("tool_calls") or []
        if tcs:
            tc = tcs[-1]
            # tool_calls format can vary slightly; capture name + args defensively
            name = getattr(tc, "function", None) or tc.get("function", tc)
            return {"raw": str(tc)[:500]}
    return {}


def run_one(
    suite_name: str = "banking",
    task_id: str = "user_task_0",
    model: str = "local",
    model_id: str = "llama3.1:8b",
    benchmark_version: str = "v1",
    logs_dir: str = "logs",
) -> str:
    """Run ONE user task with no attack and no defence; save a Trace; return the log path."""

    # 1) describe the run (this metadata is what makes it reproducible)
    cfg = RunConfig(
        model=model,
        model_id=model_id,
        suite=suite_name,
        user_task_id=task_id,
        injection_task_id=None,   # Phase 1: no attack
        attack=None,
        defense=None,             # Phase 1: no defence
        code_commit=_git_commit(),
    )
    trace = Trace(config=cfg)

    # 2) build the agent pipeline (local model, no defence)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=model,            # "local"
            model_id=model_id,    # "llama3.1:8b"
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )

    # 3) load the suite and the specific task
    suite = get_suite(benchmark_version, suite_name)
    user_task = suite.get_user_task_by_id(task_id)

    # 4) run the task INSIDE the logger so we capture the message history.
    #    The pipeline finds this logger via a global stack and calls logger.log(messages),
    #    which populates logger.messages. TraceLogger needs a delegate (NullLogger is fine).
    with TraceLogger(
        delegate=NullLogger(),
        suite_name=suite_name,
        user_task_id=task_id,
        injection_task_id=None,
        injections={},
        attack_type=None,
        pipeline_name=model_id,
    ) as logger:
        utility, security = suite.run_task_with_pipeline(
            agent_pipeline=pipeline,
            user_task=user_task,
            injection_task=None,
            injections={},
        )
        messages = getattr(logger, "messages", [])

    # 5) fill in the trace from what we captured
    trace.hops = _messages_to_hops(messages)
    trace.final_action = _final_action(messages)
    trace.attack_succeeded = bool(security)   # no attack here, so this is just the field
    trace.notes = f"utility={utility} security={security} (Phase 1: no attack/defence)"

    # 6) save one JSON log
    path = trace.save(logs_dir=logs_dir)
    print(f"\n[runner] task_completed={utility}  attack_succeeded={security}")
    print(f"[runner] hops recorded: {len(trace.hops)}")
    print(f"[runner] saved log: {path}")
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run one AgentDojo task and record a Trace.")
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--task", default="user_task_0")
    ap.add_argument("--model", default="local")
    ap.add_argument("--model-id", default="llama3.1:8b")
    ap.add_argument("--logs-dir", default="logs")
    args = ap.parse_args()

    run_one(
        suite_name=args.suite,
        task_id=args.task,
        model=args.model,
        model_id=args.model_id,
        logs_dir=args.logs_dir,
    )