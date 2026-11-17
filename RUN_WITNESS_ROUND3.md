# WITNESS round 3: one command

This round covers the fixed task finder, banking tasks, baselines on every new task, and the adaptive attacks. Same environment as before: activate the venv, set `OPENAI_API_KEY` and `LOCAL_LLM_PORT`, and have Ollama running with `qwen2.5:14b`.

## 0. Get the code

```bash
git fetch origin
git checkout design/witness-defense
git pull
```

The `logs/` folder from round 2 must still be there. Steps 5, 7, 8 and 9 replay those traces.

## 1. Run everything

```bash
python experiments/run_round3.py
```

**Expected time: about 2–3.5 hours.** You can leave it running.

| Step | What | Time |
|---|---|---|
| 1 | unit tests (expect `Ran 39 tests ... OK`) | seconds |
| 2 | find delegated-value tasks (fixed: now includes banking) | < 1 min |
| 3 | dry run: prints the banking tasks and `agent runs: about N` | seconds |
| 4 | **banking runs + 4 baselines (main compute)** | about N × 1 min + 30–60 min |
| 5 | baselines on the round-2 Slack/workspace runs (no agent runs) | about 1–1.5 h |
| 6 | adaptive attacks against WITNESS (offline) | seconds |
| 7–9 | replays (step 9 now asks the LLM planner once per task, not once per trace) | a few min |

**If it stops or crashes**, rerun from the failed step, e.g. `python experiments/run_round3.py --from 5`. The summary at the end lists each step as OK or FAILED.

**If step 3 shows many banking tasks**, you can cap step 4 with `python experiments/run_round3.py --max-tasks 6`.

## 2. Send back

Commit and push everything new in `experiments/results/`, as last time:

- `round3_log_<timestamp>.txt`: the full console output. **Most important.**
- `delegated_tasks.json`
- the new `phase4_competing_value_*banking*.json` files, plus the round-2 `phase4_competing_value_*` files (step 5 adds baseline decisions to them)
- `adaptive_offline_*.md` / `.json`
- the three new `witness_replay_*.md` / `.json`

```bash
git add experiments/results
git commit -m "Round 3 results"
git push
```
