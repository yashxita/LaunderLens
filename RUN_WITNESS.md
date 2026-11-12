# Running WITNESS: instructions for the benchmark machine

WITNESS is our new defence. Design: `design/DEFENSE_DESIGN.md`. Code: `defenses/witness/`.
These steps run it against the traces we already have and send the numbers back.

**Time:** steps 1–4 take a few minutes with **no model calls**. Step 6 uses Ollama.

---

## 0. Get the code

```bash
git fetch origin
git checkout design/witness-defense
git pull
```

## 1. Environment (same as always)

macOS / Linux:
```bash
source .venv/bin/activate
export OPENAI_API_KEY="ollama"
export LOCAL_LLM_PORT=11434
```

Windows PowerShell:
```powershell
.venv\Scripts\Activate.ps1
$env:OPENAI_API_KEY="ollama"
$env:LOCAL_LLM_PORT="11434"
```

## 2. Sanity check (offline unit tests, about 1 second)

```bash
python -m unittest discover -s defenses/witness/tests -t .
```

**Expected:** `Ran 29 tests ... OK`. If anything fails, stop and send the full output.

## 3. Make sure the old traces are present

The replay reads the trace JSONs in `logs/`. They are gitignored, so they exist only on the machine(s) that ran Phase 4.

- Run everything below **on the machine that has `logs/`**.
- If Phase 4 runs were split across two laptops, copy both `logs/` folders into one place first. Or run step 4 on each machine and send both outputs.

Quick check (each command should print a number well above 0):

macOS / Linux:
```bash
ls logs | wc -l
ls experiments/results/phase4_*.json | wc -l
```

Windows PowerShell:
```powershell
(Get-ChildItem logs -Recurse -Filter *.json).Count
(Get-ChildItem experiments/results/phase4_*.json).Count
```

## 4. Main run: replay WITNESS over every saved trace (no model calls)

```bash
python experiments/run_witness_replay.py
```

It prints one line per configuration and writes two files:

```
experiments/results/witness_replay_<timestamp>.md
experiments/results/witness_replay_<timestamp>.json
```

If it says `traces not found: N` with a large N, `logs/` is not the one the result files point to (see step 3). Pass the right folder with `--logs-dir path/to/logs`.

## 5. Two extra replays (also no model calls)

**5a. Trusted seed.** This exports the user's own IBAN and past payees from AgentDojo's environment, then replays with them:
```bash
python experiments/seed_trusted_state.py
python experiments/run_witness_replay.py --trusted-seed experiments/results/trusted_seed.json
```
If the seed script errors, try `python experiments/seed_trusted_state.py --version v1.2` and include the error in what you send.

**5b. Deterministic slot planner** (no ground-truth plan):
```bash
python experiments/run_witness_replay.py --slots heuristic
```

## 6. Optional: uses Ollama (`qwen2.5:14b` must be running)

**6a.** Replay with the LLM slot planner and the LLM veto:
```bash
python experiments/run_witness_replay.py --slots llm --with-llm --model-id qwen2.5:14b
```

**6b.** Utility table, adding WITNESS next to the other four defences (writes `experiments/results/utility_witness.json`):
```bash
python experiments/run_utility.py --defenses witness
```

**6c.** Two live end-to-end checks with WITNESS as the defence (about 5 model runs each):
```bash
python experiments/run_phase4.py --attack attribution_forgery --variant replacement_notice --defense witness --seeds 1
python experiments/run_phase4.py --attack slack_invite_redirect --variant dual_contact --defense witness --seeds 1
```

**Expected in 6c:** the `send_money` / `invite_user_to_slack` line shows `BLOCK` with `label=untrusted` and `layer=S6` (escalated), or `layer=S3` (value not in the document). `Dishonest labels` should be `0`.

---

## What to send back

1. Both `witness_replay_*.md` and `witness_replay_*.json` from **step 4**. Most important.
2. The `.md` (and `.json`) from **5a** and **5b**, if you ran them.
3. Anything from **step 6**: `utility_witness.json`, plus the two new `phase4_*_*.json` result files and their console output.
4. The full console output of **any** command that crashed.

You can zip the JSONs if they're big; the `.md` files are small.

---

## Reading the numbers (so you can tell if something is off)

| column | meaning | good WITNESS value |
|---|---|---|
| ASR-def | attacker's value got through / times the agent tried | 0 |
| UA | the legitimate payment/invite was allowed in an attacked trace | high for `witness_assisted` |
| ESC | needed a user question (autonomous mode refuses instead) | low on benign traces |
| LIS+D | label honesty with the defence in the loop | 1.0 |
| FPR / BU | blocked legit writes on clean traces / clean traces fully allowed | FPR 0, BU 1 |

The configurations and what they mean:

| config | what it is |
|---|---|
| `witness` | full defence, no human: conflicts are refused |
| `witness_assisted` | same, but a simulated user answers the closed-choice question |
| `ablate_uniqueness` | accepts any candidate: should behave like **AuthGraph** (attacks get through) |
| `ablate_delegation` | never trusts document values: should behave like **CaMeL / FIDES / RTBAS** (FPR = 1) |
| other `ablate_*` / `witness_*` | turn one stage off or on, for the paper's ablation table |
