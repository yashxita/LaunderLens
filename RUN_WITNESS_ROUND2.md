# WITNESS round 2: planner fix + more tasks

Same setup as `RUN_WITNESS.md` (activate the venv, set `OPENAI_API_KEY` and `LOCAL_LLM_PORT`, start Ollama).
Run every command from the repo root.

**Total machine time:** about 3–5 hours, mostly step 5, which can run overnight.

## 0. Get the code

```bash
git fetch origin
git checkout design/witness-defense
git pull
```

## 1. Unit tests (1 second)

```bash
python -m unittest discover -s defenses/witness/tests -t .
```

**Expected:** `Ran 33 tests ... OK`. If not, stop and send the output.

## 2. Re-run the LLM-planner replay (bug fix check, ~30–60 min)

Last round, the LLM planner blocked the bill's amount and the Slack website visit. Both are fixed. This command only re-runs that replay (no veto):

```bash
python experiments/run_witness_replay.py --slots llm --model-id qwen2.5:14b
```

**Expected:** on the `witness` row, `BU` = 1.000. In section 4 there should be **no** `BLOCKED-control` on `get_webpage`, and almost no `BLOCKED-unsupported`.

## 3. Find every task where a payee / e-mail / URL comes from a document (no model calls, <1 min)

```bash
python experiments/find_delegated_tasks.py
```

It prints the list and writes `experiments/results/delegated_tasks.json`. Send the printed list even if step 5 fails. If it errors, also try `--version v1.2` and send both outputs.

## 4. Dry run: check which tasks and payloads will be used (no model calls)

```bash
python experiments/run_generalization.py --dry-run
```

The first lines say how many agent runs step 5 needs (`agent runs: about N`). At roughly 2 minutes per run, that's your time estimate.

## 5. The real run (main compute; leave it overnight if needed)

```bash
python experiments/run_generalization.py --seeds 2
```

- This does 1 clean run plus 3 attack variants × 2 seeds per task.
- If time is short, cap it: add `--max-tasks 8`.
- If it crashes partway, rerun only the remaining tasks with `--tasks banking/user_task_X slack/user_task_Y`, using the names it printed.

Optional, if you have extra time:

| Command | Adds | Cost |
|---|---|---|
| `python experiments/run_generalization.py --seeds 2 --baselines authgraph rtbas` | old defences, using their own LLM planners | extra LLM calls, no extra agent runs |
| `python experiments/run_generalization.py --seeds 2 --oracle` | counterfactual oracle (label-honesty numbers) | **4×** the agent runs |

## 6. Score WITNESS on the new tasks (no model calls, <1 min)

```bash
python experiments/run_witness_replay.py --attacks competing_value
python experiments/run_witness_replay.py --attacks competing_value --slots llm --model-id qwen2.5:14b
```

## What to send back

1. The output of steps 1 and 3 (copy-paste is fine).
2. The `witness_replay_*.md` + `.json` files from steps 2 and 6.
3. All new `experiments/results/phase4_competing_value_*.json` files, plus `delegated_tasks.json`.
4. Console output of anything that crashed.

Easiest: commit and push everything in `experiments/results/`, as last time.

**Also, separately:** last round, 216 old traces were missing (mostly banking `label_join`, `multi_hop_reemission`, `judge_hijack`). Whoever ran those batches, please zip that machine's `logs/` folder and send it, so the old results can be replayed too.
