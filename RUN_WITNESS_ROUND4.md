# WITNESS round 4: one command (last run before the paper)

Same setup as before: activate the venv, set `OPENAI_API_KEY` and `LOCAL_LLM_PORT`, and have Ollama running with `qwen2.5:14b`. Keep the `logs/` folder from rounds 2–3.

## 0. Get the code

```bash
git fetch origin
git checkout design/witness-defense
git pull
```

## 1. Run

```bash
python experiments/run_round4.py
```

**Expected time: about 1.5 hours.**

| Step | What | Time |
|---|---|---|
| 1 | unit tests (expect `Ran 41 tests ... OK`) | seconds |
| 2 | **old defences on the clean runs of the new tasks** (their utility cost; LLM calls only) | ~45 min |
| 3 | banking `user_task_15` rerun with an attacker IBAN that doesn't clash with the prompt | ~30 min |
| 4 | old defences on that rerun's clean run | ~10 min |
| 5–8 | adaptive attacks + replays | a few min |

If time is short, skip step 3 (it's optional): `python experiments/run_round4.py --skip-agent`.

To resume after a crash, e.g. from step 4: `python experiments/run_round4.py --from 4`.

## 2. Send back

```bash
git add experiments/results
git commit -m "Round 4 results"
git push
```
