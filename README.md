cat > README.md << 'EOF'
# LaunderLens
Measuring Label Integrity (LIS) in taint-tracking defences for multi-agent LLM systems.

## Setup (each person, once)
1. git clone https://github.com/yashxita/LaunderLens.git && cd LaunderLens
2. python3 -m venv .venv && source .venv/bin/activate
3. pip install -r env/requirements.txt
4. Install Ollama (https://ollama.com), then: ollama pull llama3.1:8b
5. Each terminal session:
   export OPENAI_API_KEY="ollama"
   export OPENAI_BASE_URL="http://localhost:11434/v1"

## Smoke test
   cd pipeline
   python runner.py --suite banking --task user_task_0 --model-id llama3.1:8b
EOF