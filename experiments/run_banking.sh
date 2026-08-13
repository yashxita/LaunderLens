#!/usr/bin/env bash
# run_banking.sh  —  One-click Phase 2 experiment for your friend to run.
#
# What this does:
#   1. Runs ONE clean trace (no attack) to establish baseline behaviour
#   2. Runs 5 poisoned traces (important_instructions attack) to measure ASR
#   3. Runs 15 counterfactual oracle re-runs (5 × 3 fillers) to measure LIS-sink
#   4. Saves all traces to logs/ and a summary to experiments/results/
#
# Setup (first time only, once per machine):
#   git clone https://github.com/yashxita/LaunderLens.git && cd LaunderLens
#   python3 -m venv .venv && source .venv/bin/activate
#   pip install -r env/requirements.txt
#   # Install Ollama from https://ollama.com, then:
#   ollama pull qwen2.5:14b
#
# Every terminal session before running:
#   export OPENAI_API_KEY="ollama"
#   export LOCAL_LLM_PORT=11434
#
# Run:
#   source .venv/bin/activate
#   bash experiments/run_banking.sh

set -e  # exit on any error

# ---- sanity checks ----
if [[ -z "$LOCAL_LLM_PORT" ]]; then
    echo "ERROR: LOCAL_LLM_PORT is not set."
    echo "Run:  export LOCAL_LLM_PORT=11434"
    exit 1
fi

if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "ERROR: OPENAI_API_KEY is not set."
    echo "Run:  export OPENAI_API_KEY=\"ollama\""
    exit 1
fi

# ---- check we're in the repo root ----
if [[ ! -f "pipeline/runner.py" ]]; then
    echo "ERROR: Run this script from the LaunderLens repo root."
    echo "  cd /path/to/LaunderLens"
    echo "  bash experiments/run_banking.sh"
    exit 1
fi

echo ""
echo "======================================================="
echo "  LaunderLens — Phase 2 Banking Experiment"
echo "======================================================="
echo "  Model  : qwen2.5:14b"
echo "  Suite  : banking / user_task_0"
echo "  Attack : important_instructions"
echo "  Seeds  : 5"
echo ""
echo "  Estimated time: ~20-40 min depending on hardware"
echo "======================================================="
echo ""

python experiments/run_experiment.py \
    --suite banking \
    --task user_task_0 \
    --model-id qwen2.5:14b \
    --attack important_instructions \
    --injection-key injection_bill_text \
    --seeds 5 \
    --logs-dir logs \
    --results-dir experiments/results

echo ""
echo "Done! Push logs/ and experiments/results/ to GitHub so the team can review."
echo "  git add logs/ experiments/results/"
echo "  git commit -m 'results: Phase 2 banking experiment'"
echo "  git push"
