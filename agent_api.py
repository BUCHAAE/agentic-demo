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
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
JUICE_BASE = os.getenv("JUICE_BASE", "http://localhost:3001")

app = FastAPI()


# -------------------------
# Tool registry metadata
# -------------------------
def list_tools() -> dict:
    return {
        "tool": "list_tools",
        "tools": [
            {
                "name": "http_get",
                "description": "Fetch a specific HTTP PATH (GET) and observe status code, content type, and response preview.",
                "safety": "Read-only, no payloads, no parameter mutation."
            },
            {
                "name": "robots_txt_analyser",
                "description": "Read /robots.txt and list disallowed paths as discovery signals.",
                "safety": "Does not enforce or bypass access control."
            },
            {
                "name": "content_type_check",
                "description": "Classify endpoints as API vs HTML based on HTTP headers.",
                "safety": "Observation only, no exploitation."
            },
            {
                "name": "nmap_scan",
                "description": "Identify open TCP ports and basic services on the local host.",
                "safety": "Safe TCP connect scan only, no scripts, no exploitation. Demo-restricted to localhost."
            },
            {
                "name": "summary_generator",
                "description": "Produce a manager-friendly summary from collected observations.",
                "safety": "Presentation only, no data collection."
            }
        ]
    }


# -------------------------
# Tools (read-only)
# -------------------------
def http_get(path: str) -> dict:
    """
    PATH ONLY. Reject full URLs.
    """
    path = (path or "").strip()

    if path.startswith("http://") or path.startswith("https://"):
        raise ValueError("http_get expects a PATH like '/robots.txt' not a full URL.")

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
    """
    Robust to model variance:
      - content_type_check(path="/foo")
      - content_type_check(paths=["/foo","/bar"])
    """
    if paths is None and path is not None:
        paths = path

    if isinstance(paths, str):
        paths = [paths]

    results = []

    for p in paths or []:
        p = (p or "").strip()
        if p.startswith("http://") or p.startswith("https://"):
            raise ValueError("content_type_check expects PATH(s) like '/robots.txt' not full URLs.")
        if not p.startswith("/"):
            p = "/" + p

        url = JUICE_BASE.rstrip("/") + p
        r = requests.get(url, timeout=10, allow_redirects=True)
        ct = (r.headers.get("content-type", "") or "").lower()

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
    target = (target or "").strip()

    # Hard allowlist for demo safety
    if target not in ("localhost", "127.0.0.1"):
        raise ValueError("nmap_scan target must be 'localhost' or '127.0.0.1' only in this demo.")

    # Reject URLs, spaces, weird tokens
    if "://" in target or " " in target or "/" in target:
        raise ValueError("nmap_scan target must be a host like 'localhost' or '127.0.0.1' (not a URL).")

    if not re.match(r"^[A-Za-z0-9\.\-]+$", target):
        raise ValueError("nmap_scan target contains invalid characters.")

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
                open_ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})

    return {
        "tool": "nmap_scan",
        "target": target,
        "ports": ports,
        "open_ports": open_ports,
        "raw_output_preview": proc.stdout[:800],
        "return_code": proc.returncode,
        "stderr_preview": (proc.stderr or "")[:400],
    }


# -------------------------
# Summariser (fallback)
# -------------------------
def summary_generator(observations: list[dict]) -> dict:
    rows = []
    bullets = []

    for obs in observations:
        tool = obs.get("tool")
        res = obs.get("result", {})

        if tool == "content_type_check":
            for r in res.get("results", []):
                rows.append({
                    "path": r.get("path", ""),
                    "status": r.get("status_code", ""),
                    "content_type": r.get("content_type", ""),
                    "classification": "HTML page" if r.get("is_html") else "API(JSON)" if r.get("is_api") else "other",
                    "evidence": (r.get("body_preview", "") or "")[:120]
                })

        if tool == "http_get":
            bullets.append(
                f"{res.get('url','')} returned {res.get('status_code','?')} with {res.get('content_type','')}"
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
        + "\n\n### Summary (observations only)\n\n"
        + "\n".join(f"- {b}" for b in bullets)
        + "\n\nNote: these are observations/signals, not confirmed vulnerabilities."
    )

    return {"tool": "summary_generator", "summary": summary}


TOOLS = {
    "http_get": http_get,
    "robots_txt_analyser": robots_txt_analyser,
    "content_type_check": content_type_check,
    "nmap_scan": nmap_scan,
    "summary_generator": summary_generator,
    "list_tools": list_tools,
}


# -------------------------
# Prompts
# -------------------------
SYSTEM_PROMPT = f"""You are a supervised security reconnaissance assistant for OWASP Juice Shop.
Your job is to help a human understand the application surface area and where to focus next.

TARGET (do not invent):
- The application under test is OWASP Juice Shop at JUICE_BASE = {JUICE_BASE}
- Tools operate ONLY against JUICE_BASE using PATHS (e.g. /robots.txt)
- nmap_scan target MUST be localhost or 127.0.0.1 only

CRITICAL RULES:
- Never invent endpoints, counts, or results. Use tools to gather evidence.
- If you want to use a tool, your ENTIRE message MUST be the JSON object only (no text before/after).
- If you are not calling a tool, do NOT output JSON at all.
- Only call tools that exist exactly as defined.

STRICT RULES:
- No exploitation. No payloads. No brute force. Observation only.
- Use nmap_scan only for local surface discovery. No scripts, no OS detection.
- Use only the tools listed below.

TOOL CALL FORMAT (JSON ONLY):
  {{"tool":"<name>","args":{{...}}}}

TOOLS:
1) http_get(path: str) - fetch a PATH and observe status/content-type/preview
2) robots_txt_analyser() - read /robots.txt and list disallowed paths
3) content_type_check(path: str) - classify whether a path looks like API/data vs page
4) nmap_scan(target: str, ports: str) - identify open TCP ports and basic services (observation only)
5) summary_generator(observations: list[dict]) - produce a manager-friendly briefing
6) list_tools() - list available tools

IMPORTANT OUTPUT STYLE (when NOT calling a tool):
- Use short headings and bullets for readability.
- Always include:
  - What we know (evidence)
  - What we suspect (interpretation, clearly labelled)
  - What we don’t know yet
  - Where a human should focus next (SAFE, non-exploitative)
  - Confidence (High/Medium/Low on key claims)

Keep it manager-friendly but specific.
"""


# -------------------------
# Ollama helpers
# -------------------------
def render_prompt(messages: list[dict]) -> str:
    parts = []
    for m in messages:
        role = (m.get("role") or "user").upper()
        content = m.get("content") or ""
        parts.append(f"{role}:\n{content}\n")
    parts.append("ASSISTANT:\n")
    return "\n".join(parts)


def call_ollama(messages: list[dict]) -> str:
    """
    Calls Ollama using /api/generate (single prompt string).
    """
    host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    model = os.getenv("OLLAMA_MODEL", MODEL)
    url = f"{host}/api/generate"

    prompt = render_prompt(messages)
    payload = {"model": model, "prompt": prompt, "stream": False}

    r = requests.post(url, json=payload, timeout=120)
    if not r.ok:
        raise RuntimeError(f"Ollama error {r.status_code}: {r.text}")

    data = r.json()
    return data.get("response", "")


def prettify_if_json(text: str) -> str:
    t = (text or "").strip()
    if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
        try:
            obj = json.loads(t)
            if isinstance(obj, dict) and "tools" in obj:
                lines = ["### Tools in this demo", ""]
                for tool in obj.get("tools", []):
                    name = tool.get("name", "unknown")
                    desc = tool.get("description", "")
                    lines.append(f"- **{name}** — {desc}")
                return "\n".join(lines)
            return "```json\n" + json.dumps(obj, indent=2) + "\n```"
        except Exception:
            return text
    return text


def parse_tool_call(text: str):
    """
    Tool calls must be JSON ONLY (no extra text).
    """
    text = (text or "").strip()
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


# -------------------------
# NEW: Safe recon playbook + strong synthesis
# -------------------------
SAFE_DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/manifest.json"
]


def dedupe_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def run_safe_recon_playbook() -> list[dict]:
    """
    Fixed safe plan:
      1) robots.txt
      2) verify + classify candidate paths
      3) nmap localhost (basic observation)
    """
    observations = []

    robots_res = robots_txt_analyser()
    observations.append({"tool": "robots_txt_analyser", "result": robots_res})

    disallowed = (robots_res.get("disallow_paths") or [])[:20]
    candidate_paths = dedupe_keep_order(SAFE_DEFAULT_PATHS + disallowed)

    for p in candidate_paths:
        hg = http_get(p)
        observations.append({"tool": "http_get", "result": hg})

        if hg.get("status_code") in (200, 301, 302, 401, 403):
            ct = content_type_check(path=p)
            observations.append({"tool": "content_type_check", "result": ct})

    nm = nmap_scan(target="127.0.0.1", ports="1-10000")
    observations.append({"tool": "nmap_scan", "result": nm})

    return observations


def build_security_handoff_prompt(observations: list[dict]) -> str:
    return f"""
You are a supervised security reconnaissance assistant. Observation-only. Do NOT propose exploitation or payloads.

Write a concise security handoff with headings:

## What we know (evidence)
- bullets grounded in the observations (include key paths, status codes, content-types, and any open ports)

## What we suspect (interpretation)
- clearly label as interpretation, not fact
- include “expected for OWASP Juice Shop” vs “would be concerning in production”

## What we don’t know yet
- unknowns that cannot be concluded from the evidence

## Where a human should focus next (safe)
- safe activities only: browser devtools/network review, JS bundle review, auth/session flow review
- no exploit steps, no attack payloads

## Confidence
- list 3–6 key claims with High/Medium/Low confidence and why

Observations JSON:
{json.dumps(observations, indent=2)}
""".strip()


def generate_security_handoff(observations: list[dict]) -> str:
    prompt = build_security_handoff_prompt(observations)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    return call_ollama(messages)


# -------------------------
# API endpoint
# -------------------------
@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    user_messages = body.get("messages", [])
    if not user_messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    # Detect simple "run the recon" triggers so the demo feels agentic
    last_user = ""
    for m in reversed(user_messages):
        if m.get("role") == "user":
            last_user = (m.get("content") or "").strip().lower()
            break

    recon_triggers = {
        "next",
        "start",
        "start recon",
        "start reconnaissance",
        "run recon",
        "recon",
        "begin recon",
        "begin reconnaissance",
        "do recon",
        "do reconnaissance",
    }

    if last_user in recon_triggers:
        observations = run_safe_recon_playbook()
        final_text = generate_security_handoff(observations)
        final_text = prettify_if_json(final_text)

        resp = {
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}
            ],
            "model": MODEL,
        }
        return JSONResponse(resp)

    # Otherwise: normal tool-using chat loop (bounded for safety)
    convo = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    observations: list[dict] = []
    final_text = None

    for _ in range(12):
        llm_out = call_ollama(convo)
        tool_call = parse_tool_call(llm_out)

        # No tool call => final answer in prose
        if not tool_call:
            final_text = llm_out
            break

        tool = tool_call["tool"]
        args = tool_call.get("args", {}) or {}

        if tool not in TOOLS:
            final_text = f"I can't use tool '{tool}'. Allowed: {', '.join(TOOLS.keys())}."
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
        convo.append({"role": "user", "content": f"Tool result:\n{json.dumps(result, indent=2)}"})

    # If the model never produced a prose answer, generate a proper handoff
    if final_text is None and observations:
        final_text = generate_security_handoff(observations)

    if final_text is None:
        final_text = "Stopped after max steps (demo safety limit)."

    final_text = prettify_if_json(final_text)

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