# LaunderLens
Measuring Label Integrity (LIS) in taint-tracking defences for multi-agent LLM systems.

## Setup (each person, once)
1. git clone https://github.com/yashxita/LaunderLens.git && cd LaunderLens
2. python3 -m venv .venv && source .venv/bin/activate
3. pip install -r env/requirements.txt
   python patches/apply_agentdojo_patch.py   # only if qwen2.5 tool calls fail to parse (needed on Windows, not on macOS); see patches/README.md
4. Install Ollama (https://ollama.com), then: ollama pull llama3.1:8b
5. Each terminal session:
   export OPENAI_API_KEY="ollama"
   export OPENAI_BASE_URL="http://localhost:11434/v1"
   export LOCAL_LLM_PORT=11434   # AgentDojo's local provider reads this, not OPENAI_BASE_URL

6. Rajveer : 
               $env:OPENAI_API_KEY="ollama"
               $env:OPENAI_BASE_URL="http://localhost:11434/v1"
               $env:LOCAL_LLM_PORT="11434"

## Smoke test
   cd pipeline
   python runner.py --suite banking --task user_task_0 --model-id llama3.1:8b
EOF