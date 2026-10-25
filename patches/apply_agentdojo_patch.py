"""
apply_agentdojo_patch.py  —  apply LaunderLens's one-line-area fix to AgentDojo 0.1.35.

Why: qwen2.5 served by Ollama often writes a tool call as
    <function=send_money>{"recipient": ..., "amount": ...}
    ```
without a closing </function> tag. AgentDojo's _parse_model_output() then
captures the trailing Markdown fence, json.loads() fails, and the tool is never
executed. All LaunderLens runs used AgentDojo with the fences stripped before
parsing (PROGRESS.md, 2026-08-16, "Fix 1"). This script applies the same change
to the AgentDojo copy installed in the current environment.

Usage (inside the project's virtual environment):
    python patches/apply_agentdojo_patch.py
It is idempotent: running it twice does nothing the second time.
"""
import importlib.util
import os
import sys

MARKER = "# LaunderLens patch: qwen2.5 often omits </function>"
OLD = "    raw_json = completion[start_idx:end_idx].strip()\n"
NEW = (
    OLD
    + "    " + MARKER + " and follows the JSON with a\n"
    "    # Markdown code fence, so the captured text ends in ``` and json.loads fails.\n"
    "    # Strip surrounding code fences before parsing.\n"
    "    raw_json = re.sub(r\"^```(?:json)?\\s*\", \"\", raw_json)\n"
    "    raw_json = re.sub(r\"\\s*```.*$\", \"\", raw_json, flags=re.S).strip()\n"
)

spec = importlib.util.find_spec("agentdojo")
if spec is None or not spec.submodule_search_locations:
    sys.exit("agentdojo is not installed in this environment")
path = os.path.join(list(spec.submodule_search_locations)[0], "agent_pipeline", "llms", "local_llm.py")
src = open(path, encoding="utf-8").read()
if MARKER in src:
    print(f"already patched: {path}")
    sys.exit(0)
if src.count(OLD) != 1:
    sys.exit(f"unexpected local_llm.py layout (is this AgentDojo 0.1.35?): {path}")
open(path, "w", encoding="utf-8").write(src.replace(OLD, NEW))
print(f"patched: {path}")
