# Patches to third-party code

LaunderLens used AgentDojo 0.1.35. On the Windows machine only, one local change was made to
`agentdojo/agent_pipeline/llms/local_llm.py`: code fences around a tool call's
JSON arguments are stripped before `json.loads` (see PROGRESS.md, 2026-08-16,
"Fix 1"). On that machine, without it, stock AgentDojo could not parse qwen2.5:14b tool calls.
On the macOS machine the stock file worked unchanged (installed 5 Aug, never modified;
verified 25 Oct with a clean banking run that executed send_money). The patch only affects
whether a tool call is read, never its content. This file was rebuilt from the PROGRESS.md
description and should be compared with the Windows machine's copy.

Apply it once after `pip install -r env/requirements.txt`:

    python patches/apply_agentdojo_patch.py

The same change as a unified diff: `agentdojo_0.1.35_local_llm_strip_fences.patch`.
