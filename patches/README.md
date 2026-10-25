# Patches to third-party code

All LaunderLens runs used AgentDojo 0.1.35 with one local change to
`agentdojo/agent_pipeline/llms/local_llm.py`: code fences around a tool call's
JSON arguments are stripped before `json.loads` (see PROGRESS.md, 2026-08-16,
"Fix 1"). Without it, stock AgentDojo cannot parse most qwen2.5:14b tool calls
and the agent never reaches `send_money`.

Apply it once after `pip install -r env/requirements.txt`:

    python patches/apply_agentdojo_patch.py

The same change as a unified diff: `agentdojo_0.1.35_local_llm_strip_fences.patch`.
