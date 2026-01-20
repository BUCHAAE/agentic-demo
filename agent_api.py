import json
import os
import re
import requests
import subprocess
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# -------------------------
# Config
# -------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("MODEL", "llama3.1:8b")
JUICE_BASE = os.getenv("JUICE_BASE", "http://localhost:3001")

app = FastAPI()



def list_tools() -> dict:
    return {
        "tool": "list_tools",
        "tools": [
            {
                "name": "http_get",
                "description": "Fetch a specific HTTP path and observe status code, content type, and response preview (GET only).",
                "safety": "Read-only, no payloads, no parameter mutation."
            },
            {
                "name": "robots_txt_analyser",
                "description": "Read /robots.txt and list disallowed paths as discovery signals.",
                "safety": "Does not enforce or bypass access control."
            },
            {
                "name": "content_type_check",
                "description": "Classify endpoints as API vs HTML based on HTTP headers and response body.",
                "safety": "Observation only, no inference beyond evidence."
            },
            {
                "name": "nmap_scan",
                "description": "Identify open TCP ports and basic services on a target host.",
                "safety": "Safe TCP connect scan only, no scripts, no exploitation."
            },
            {
                "name": "summary_generator",
                "description": "Produce a manager-friendly summary from collected observations.",
                "safety": "Presentation only, no data collection."
            }
        ]
    }



# -------------------------
# Tools (4)
# -------------------------
def http_get(path: str) -> dict:
    if not path.startswith("/"):
        path = "/" + path
    url = JUICE_BASE.rstrip("/") + path
    r = requests.get(url, timeout=10)
    return {
        "tool": "http_get",
        "url": url,
        "status_code": r.status_code,
        "content_type": r.headers.get("content-type", ""),
        "body_preview": (r.text or "")[:500],
    }


def robots_txt_analyser() -> dict:
    url = JUICE_BASE.rstrip("/") + "/robots.txt"
    r = requests.get(url, timeout=10)
    disallow = []
    if r.ok and r.text:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                disallow.append(line.split(":", 1)[1].strip() or "/")
    return {
        "tool": "robots_txt_analyser",
        "url": url,
        "status_code": r.status_code,
        "disallow_paths": disallow[:30],
        "raw_preview": (r.text or "")[:500],
    }

def content_type_check(path=None, paths=None):
    # Normalise inputs so the tool is robust to model variance
    if paths is None and path is not None:
        paths = path

    if isinstance(paths, str):
        paths = [paths]

    results = []

    for p in paths or []:
        if not p.startswith("/"):
            p = "/" + p

        url = JUICE_BASE.rstrip("/") + p
        r = requests.get(url, timeout=10, allow_redirects=True)

        ct = r.headers.get("content-type", "").lower()

        results.append({
            "path": p,
            "status_code": r.status_code,
            "content_type": ct,
            "is_api": "application/json" in ct,
            "is_html": "text/html" in ct,
            "body_preview": (r.text or "")[:200],
        })

    return {
        "tool": "content_type_check",
        "results": results,
    }





def nmap_scan(target: str = "localhost", ports: str = "1-65535") -> dict:
    """
    Safe, read-only Nmap scan (demo-friendly):
    - TCP connect scan only (-sT)
    - No scripts, no OS detection
    - Intended for local lab / training environments
    """
    cmd = ["nmap", "-sT", "-Pn", "-p", ports, target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as e:
        return {"tool": "nmap_scan", "target": target, "ports": ports, "error": str(e)}

    open_ports = []
    for line in proc.stdout.splitlines():
        # Example: "3001/tcp open  http"
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append(
                    {"port": parts[0], "state": parts[1], "service": parts[2]}
                )

    return {
        "tool": "nmap_scan",
        "target": target,
        "ports": ports,
        "open_ports": open_ports,
        "raw_output_preview": proc.stdout[:800],
        "return_code": proc.returncode,
        "stderr_preview": (proc.stderr or "")[:400],
    }

def summary_generator(observations: list[dict]) -> dict:
    rows = []
    bullets = []

    for obs in observations:
        tool = obs["tool"]
        res = obs["result"]

        if tool == "content_type_check":
            for r in res.get("results", []):
                rows.append({
                    "path": r["path"],
                    "status": r["status_code"],
                    "content_type": r["content_type"],
                    "classification": "HTML page" if r["is_html"] else "API(JSON)" if r["is_api"] else "other",
                    "evidence": r.get("body_preview", "")[:120]
                })

        if tool == "http_get":
            bullets.append(
                f"{res['url']} returned {res['status_code']} with {res['content_type']}"
            )

        if tool == "nmap_scan":
            for p in res.get("open_ports", []):
                port = p.get("port", "")
                svc = p.get("service", "")
                if port and svc:
                    bullets.append(f"{port} appears open ({svc})")
                elif port:
                    bullets.append(f"{port} appears open")

        if tool == "robots_txt_analyser":
            if "/ftp" in res.get("disallow_paths", []):
                bullets.append("robots.txt references /ftp (robots exclusion is not access control)")

    # Build table text
    table_lines = [
        "path | status_code | content_type | classification | evidence_1st_120_chars",
        "--- | --- | --- | --- | ---"
    ]
    for r in rows:
        table_lines.append(
            f"{r['path']} | {r['status']} | {r['content_type']} | {r['classification']} | {r['evidence']}"
        )

    summary = (
        "### Evidence table\n\n"
        + "\n".join(table_lines)
        + "\n\n### Manager summary\n\n"
        + "\n".join(f"- {b}" for b in bullets)
        + "\n\nNote: these are observations/signals, not confirmed vulnerabilities."
    )

    return {
        "tool": "summary_generator",
        "summary": summary
    }



TOOLS = {
    "http_get": http_get,
    "robots_txt_analyser": robots_txt_analyser,
    "content_type_check": content_type_check,
    "nmap_scan": nmap_scan,
    "summary_generator": summary_generator,
    "list_tools": list_tools,        # 👈 HERE
}

SYSTEM_PROMPT = """You are a supervised security reconnaissance assistant for OWASP Juice Shop.
Your job is to help a human understand the application surface area and where to focus next.

CRITICAL RULES:
- Never invent endpoints, counts, or results. Use tools to gather evidence.
- If you want to use a tool, your ENTIRE message MUST be the JSON object only (no text before/after).
- If you are not calling a tool, do NOT output JSON at all.
- Only call tools that exist exactly as defined.

STRICT RULES:
- No exploitation. No payloads. No brute force. Observation only.
- Use nmap_scan only for local surface discovery. No scripts, no OS detection.
- Use only the tools listed below.
- If you want to use a tool, output JSON ONLY in this exact format:
  {"tool":"<name>","args":{...}}

TOOLS:
1) http_get(path: str) - fetch a path and observe status/content-type/preview
2) robots_txt_analyser() - read /robots.txt and list disallowed paths
3) content_type_check(path: str) - classify whether a path looks like API/data vs page
4) summary_generator(observations: list[str]) - produce a manager-friendly briefing
5) nmap_scan(target: str, ports: str) - identify open TCP ports and basic services (observation only)

If no tool is needed, answer normally in plain English.
Keep outputs short and manager-friendly.
"""

TOOL_CONTROLLER_PROMPT = """TOOL_CALL_ONLY MODE.
Return ONLY a single JSON object for the next tool call.
No prose. No markdown. No code fences. No backticks.
JSON format:
{"tool":"<name>","args":{...}}

Allowed tools:
- http_get (args: {"path":"/..."})
- robots_txt_analyser (args: {})
- content_type_check (args: {"path":"/..."})
- summary_generator (args: {"observations":[...]} )
- nmap_scan (args: {"target":"localhost","ports":"1-65535"})

If you are unsure, choose robots_txt_analyser first.
"""


def call_ollama(messages: list[dict]) -> str:
    payload = {"model": MODEL, "messages": messages, "stream": False}
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["message"]["content"]


def parse_tool_call(text: str):
    # Tool calls must be JSON ONLY (no extra text)
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "tool" in obj:
            if "args" not in obj or obj["args"] is None:
                obj["args"] = {}
            if isinstance(obj["args"], dict):
                return obj
    except Exception:
        return None
    return None


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    user_messages = body.get("messages", [])
    if not user_messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    convo = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    observations: list[dict] = []
    observations: list[dict] = []
    final_text = None

    # bounded loop for demo safety
    for _ in range(12):
        llm_out = call_ollama(convo)
        tool_call = parse_tool_call(llm_out)

        # If it didn't return pure JSON, force TOOL_CALL_ONLY
        if not tool_call:
            convo.append({"role": "assistant", "content": llm_out})
            convo.append({"role": "user", "content": TOOL_CONTROLLER_PROMPT})
            llm_out = call_ollama(convo)
            tool_call = parse_tool_call(llm_out)

        # If still not a tool call, stop (demo safety)
        if not tool_call:
            final_text = (
                "Model did not produce a valid tool call. "
                "Stopping (demo safety)."
            )
            break

        tool = tool_call["tool"]
        args = tool_call.get("args", {}) or {}

        # Prevent the model from ending the loop early with summary_generator
        if tool == "summary_generator":
            observations.append({"tool": "controller", "result": {"note": "Model requested summary generation"}})
            # Do NOT execute it here; summary is controlled by the agent
            continue


        if tool not in TOOLS:
            final_text = (
                f"I can't use tool '{tool}'. Allowed: {', '.join(TOOLS.keys())}."
            )
            break

        # Execute tool safely
        try:
            result = TOOLS[tool](**args) if args else TOOLS[tool]()
        except Exception as e:
            final_text = f"Tool '{tool}' failed: {e}"
            break

        observations.append({"tool": tool, "result": result})


        # Add tool request + result back into conversation
        convo.append({"role": "assistant", "content": llm_out})
        convo.append(
            {
                "role": "user",
                "content": f"Tool result:\n{json.dumps(result, indent=2)}",
            }
        )



    if final_text is None and observations:
        result = summary_generator(observations)
        final_text = result["summary"]

    if final_text is None:
        final_text = "Stopped after max steps (demo safety limit)."


    # OpenAI-compatible shape for Open WebUI
    resp = {
        "id": "chatcmpl-agentic-demo",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": final_text},
                "finish_reason": "stop",
            }
        ],
        "model": MODEL,
    }
    return JSONResponse(resp)