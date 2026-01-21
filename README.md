# Agentic Demo (Juice Shop + Ollama + FastAPI + Streamlit) ## Run
bash
source /home/buchaae/agentic-demo/agent-env/bin/activate
/home/buchaae/agentic-demo/agent-env/bin/python /home/buchaae/agentic-demo/start-agentic.py

## URLs
- Juice Shop: http://localhost:3001
- Ollama: http://localhost:11434
- API: http://localhost:8000
- Streamlit: http://localhost:8501


## Demo prompts (copy/paste)

### Prompt 0 — Intro / Explain the demo (non-technical)
You are an agentic security assistant.

Explain what tools are available to you in this demo, what each tool does, and when you would choose to use them.

Please include:
- The vulnerable application being tested
- Any reconnaissance or scanning capability
- How the language model is involved
- How decisions are made step-by-step

Keep the explanation clear and suitable for a non-technical audience, but accurate.

---

### Prompt pack (recommended run order)

#### Prompt 1 — Orientation & guardrails (sets trust)
What tools do you have available, what does each one do, and what are you explicitly not allowed to do?

#### Prompt 2 — Safest first step (shows decision-making)
Start reconnaissance of OWASP Juice Shop using the safest possible first step. Explain why you chose it.

#### Prompt 3 — Verify + classify what you found (evidence-driven)
Based on what you discovered, verify which paths actually exist and classify them as pages or APIs.

#### Prompt 4 — Confirm the exposed services (famous tool, but safe)
Confirm that the exposed services match what we expect for this local environment. Do not probe beyond basic observation.

#### Prompt 5 — Executive summary (the payoff)
Summarise what we know, what we don’t know yet, and where a human security engineer should focus next.

---

### Optional bonus prompt (if time allows)
What evidence supports your conclusions, and what assumptions did you avoid making?



export OLLAMA_MODEL="llama3.1:8b"


echo $OLLAMA_MODEL