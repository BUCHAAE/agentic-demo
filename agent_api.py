"""
agent_api.py (updated)

Key upgrades vs your original:

1) Uniform ObservationStore (timestamps, tool, args, ok/error, data) across BOTH playbook + interactive mode.
2) Stricter PATH validation (reject full URLs, query strings, fragments, disallowed chars).
3) Safer evidence capture: http_get + content_type_check do NOT follow redirects; record Location header.
4) Ollama integration moved to /api/chat (more reliable multi-turn behaviour).
5) Executive report is hard-gated:
   - Step 1: deterministic evidence pack (table + bullets) generated locally (no hallucinations)
   - Step 2: LLM is only allowed to REPHRASE that evidence into the required 6-section exec format.
   - The LLM is explicitly forbidden from adding facts not present in evidence pack.

This keeps your demo UX (FastAPI /v1/chat/completions) while materially reducing “rubbish output”.
"""

import json
import os
import re
import time
import requests
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# -------------------------
# Config
# -------------------------
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
JUICE_BASE = os.getenv("JUICE_BASE", "http://localhost:3001")

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "30"))
MAX_STEPS = int(os.getenv("MAX_STEPS", "12"))
MAX_TOOL_CALLS = int(os.getenv("MAX_TOOL_CALLS", "12"))

app = FastAPI()

# -------------------------
# Strict validators (guardrails)
# -------------------------
# Allow only URL path chars. No scheme, no host. No querystring or fragment.
_PATH_RE = re.compile(r"^/([A-Za-z0-9\-._~!$&'()*+,;=:@/]*)$")


def validate_path(path: str) -> Tuple[bool, str, str]:
    """
    Returns: (ok, error_message, normalised_path)
    - rejects full URLs, query strings, fragments
    - enforces leading '/'
    - allowlists characters
    """
    p = (path or "").strip()
    if not p:
        return False, "Path must be a non-empty string.", ""

    if "://" in p or p.startswith("http://") or p.startswith("https://"):
        return False, "PATH only. Full URLs are not permitted.", ""

    # reject query string and fragment to avoid “parameterised” calls
    if "?" in p or "#" in p:
        return False, "Query strings and fragments are not permitted. Provide a clean PATH only.", ""

    if not p.startswith("/"):
        p = "/" + p

    if not _PATH_RE.match(p):
        return False, "Path contains disallowed characters. Provide a simple URL path.", ""

    return True, "", p


def safe_join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def require_localhost(target: str) -> Tuple[bool, str]:
    t = (target or "").strip()
    if t not in ("localhost", "127.0.0.1"):
        return False, "nmap_scan is restricted to 'localhost' or '127.0.0.1' only in this demo."
    if "://" in t or "/" in t or " " in t:
        return False, "nmap_scan target must be a host only (no URL/path)."
    if not re.match(r"^[A-Za-z0-9.\-]+$", t):
        return False, "nmap_scan target contains invalid characters."
    return True, ""


# -------------------------
# Observation store (system of record)
# -------------------------
@dataclass
class Observation:
    ts_utc: float
    tool: str
    args: Dict[str, Any]
    ok: bool
    error: Optional[str]
    data: Dict[str, Any]


class ObservationStore:
    def __init__(self) -> None:
        self._items: List[Observation] = []

    def add(self, tool: str, args: Dict[str, Any], ok: bool, data: Dict[str, Any], error: Optional[str] = None) -> None:
        self._items.append(
            Observation(
                ts_utc=time.time(),
                tool=tool,
                args=args or {},
                ok=bool(ok),
                error=error,
                data=data or {},
            )
        )

    def all(self) -> List[Dict[str, Any]]:
        return [asdict(o) for o in self._items]

    def to_json(self) -> str:
        return json.dumps(self.all(), indent=2)

    def clear(self) -> None:
        self._items = []


# -------------------------
# Tool registry metadata
# -------------------------
def list_tools() -> dict:
    return {
        "tool": "list_tools",
        "tools": [
            {
                "name": "http_get",
                "description": "Fetch an HTTP PATH (GET) and observe status code, headers subset, and response preview. No redirects.",
                "safety": "Read-only, PATH-only, no parameters, no payloads."
            },
            {
                "name": "robots_txt_analyser",
                "description": "Read /robots.txt and list Disallow paths as discovery signals.",
                "safety": "Observation only; robots rules are not access control."
            },
            {
                "name": "content_type_check",
                "description": "Classify a PATH as HTML vs JSON vs other based on response headers. No redirects.",
                "safety": "Observation only."
            },
            {
                "name": "nmap_scan",
                "description": "Identify open TCP ports and basic services on the local host.",
                "safety": "Safe TCP connect scan only; demo-restricted to localhost/127.0.0.1."
            },
            {
                "name": "summary_generator",
                "description": "Deterministic evidence pack (table + bullets) from observations (no LLM).",
                "safety": "Presentation only; does not collect data."
            }
        ]
    }


# -------------------------
# Tools (read-only, strongly constrained)
# -------------------------
def http_get(path: str) -> dict:
    ok, err, p = validate_path(path)
    if not ok:
        raise ValueError(err)

    url = safe_join(JUICE_BASE, p)
    r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False)

    ct = r.headers.get("content-type", "")
    loc = r.headers.get("location", "")
    preview = (r.text or "")[:500]

    return {
        "tool": "http_get",
        "url": url,
        "path": p,
        "status_code": r.status_code,
        "content_type": ct,
        "headers_subset": {
            "content-type": ct,
            "server": r.headers.get("server", ""),
            "x-powered-by": r.headers.get("x-powered-by", ""),
            "location": loc,
        },
        "body_preview": preview,
    }


def robots_txt_analyser() -> dict:
    url = safe_join(JUICE_BASE, "/robots.txt")
    r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False)
    disallow = []

    if r.ok and r.text:
        for line in r.text.splitlines():
            s = line.strip()
            if s.lower().startswith("disallow:"):
                val = s.split(":", 1)[1].strip()
                if val:
                    disallow.append(val)

    return {
        "tool": "robots_txt_analyser",
        "url": url,
        "status_code": r.status_code,
        "content_type": r.headers.get("content-type", ""),
        "disallow_paths": disallow[:50],
        "raw_preview": (r.text or "")[:500],
    }


def content_type_check(path: Optional[str] = None, paths: Optional[Any] = None) -> dict:
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
    for raw in (paths or []):
        ok, err, p = validate_path(raw)
        if not ok:
            raise ValueError(err)

        url = safe_join(JUICE_BASE, p)
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False)

        ct = (r.headers.get("content-type", "") or "").lower()
        loc = r.headers.get("location", "")

        kind = "unknown"
        if "application/json" in ct:
            kind = "api_or_data_endpoint"
        elif "text/html" in ct:
            kind = "web_page"
        elif ct:
            kind = "other_content"

        results.append({
            "path": p,
            "url": url,
            "status_code": r.status_code,
            "content_type": ct,
            "classification": kind,
            "location": loc,
            "body_preview": (r.text or "")[:200],
        })

    return {"tool": "content_type_check", "results": results}


def nmap_scan(target: str = "localhost", ports: str = "1-10000") -> dict:
    t = (target or "").strip()
    ok, err = require_localhost(t)
    if not ok:
        raise ValueError(err)

    # Safer defaults: avoid full 1-65535 unless you intentionally set it.
    ports = (ports or "1-10000").strip()
    if not re.match(r"^[0-9,\-]+$", ports):
        raise ValueError("ports must be numeric ranges like '1-10000' or '80,443'.")

    cmd = ["nmap", "-sT", "-Pn", "-n", "-p", ports, t]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=NMAP_TIMEOUT,
    )

    open_ports = []
    for line in (proc.stdout or "").splitlines():
        # Example: "3001/tcp open  http"
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})

    return {
        "tool": "nmap_scan",
        "target": t,
        "ports": ports,
        "open_ports": open_ports,
        "raw_output_preview": (proc.stdout or "")[:1200],
        "return_code": proc.returncode,
        "stderr_preview": (proc.stderr or "")[:400],
        "command": " ".join(cmd),
    }


# -------------------------
# Deterministic evidence pack (NO LLM)
# -------------------------
def summary_generator(observations: List[Dict[str, Any]]) -> dict:
    """
    Produce a stable, evidence-only pack:
    - Key bullets (ports, paths, status codes, content types)
    - Evidence table (path/status/ctype/classification)
    This is the “ground truth” input to the LLM for the exec report.
    """
    bullets: List[str] = []
    rows: List[Dict[str, str]] = []

    for obs in observations:
        tool = obs.get("tool")
        ok = obs.get("ok", False)
        err = obs.get("error")
        data = obs.get("data", {}) or {}
        args = obs.get("args", {}) or {}

        if not ok:
            bullets.append(f"{tool} failed for args={args}: {err}")
            continue

        if tool == "nmap_scan":
            for p in data.get("open_ports", []) or []:
                port = p.get("port", "")
                svc = p.get("service", "")
                if port and svc:
                    bullets.append(f"Port {port} reported open ({svc}) on {data.get('target')}")
                elif port:
                    bullets.append(f"Port {port} reported open on {data.get('target')}")

        if tool == "http_get":
            bullets.append(
                f"{data.get('path','')} returned {data.get('status_code')} "
                f"({data.get('content_type','') or 'no content-type'})"
                + (f"; Location={data.get('headers_subset',{}).get('location','')}" if data.get("headers_subset", {}).get("location") else "")
            )

        if tool == "robots_txt_analyser":
            bullets.append(f"/robots.txt returned {data.get('status_code')} with {data.get('content_type','')}")
            dis = data.get("disallow_paths", []) or []
            if dis:
                bullets.append(f"/robots.txt disallows {len(dis)} path(s): {', '.join(dis[:10])}" + ("…" if len(dis) > 10 else ""))

        if tool == "content_type_check":
            for r in data.get("results", []) or []:
                rows.append({
                    "path": str(r.get("path", "")),
                    "status_code": str(r.get("status_code", "")),
                    "content_type": str(r.get("content_type", "")),
                    "classification": str(r.get("classification", "")),
                    "location": str(r.get("location", "")),
                    "evidence_preview": (r.get("body_preview", "") or "")[:120].replace("\n", " "),
                })

    table_lines = [
        "path | status_code | content_type | classification | location | evidence_1st_120_chars",
        "--- | --- | --- | --- | --- | ---"
    ]
    for r in rows:
        table_lines.append(
            f"{r['path']} | {r['status_code']} | {r['content_type']} | {r['classification']} | {r['location']} | {r['evidence_preview']}"
        )

    evidence_pack = (
        "### Evidence table\n\n"
        + "\n".join(table_lines)
        + "\n\n### Evidence bullets\n\n"
        + "\n".join(f"- {b}" for b in bullets)
        + "\n\nNote: This pack is strictly observational and does not assert vulnerabilities."
    )

    return {"tool": "summary_generator", "evidence_pack": evidence_pack, "bullets_count": len(bullets), "rows_count": len(rows)}


TOOLS = {
    "http_get": http_get,
    "robots_txt_analyser": robots_txt_analyser,
    "content_type_check": content_type_check,
    "nmap_scan": nmap_scan,
    "summary_generator": summary_generator,
    "list_tools": list_tools,
}

# -------------------------
# Prompts (exec report spec)
# -------------------------
EXEC_REPORT_SYSTEM_PROMPT = f"""You are a senior security consultant producing a reconnaissance summary for leadership.

NON-NEGOTIABLE RULES:
- You may only report findings explicitly supported by the EVIDENCE PACK provided.
- Do not invent endpoints, vulnerabilities, technologies, or behaviours.
- If something cannot be confirmed, state that clearly.
- Use professional, calm, evidence-based language.
- Do NOT add any facts beyond the evidence pack.
- If the evidence is insufficient for a section, state that it cannot be concluded from observations.

OUTPUT FORMAT (exact headings required):
1. Executive Summary (High Impact)
2. Key Observations
3. Evidence & Method
4. Security Interpretation (Non-Exploitative)
5. Limitations & Guardrails
6. Recommended Next Steps

TARGET CONTEXT:
- Application under observation: OWASP Juice Shop
- Base URL: {JUICE_BASE}
- Tooling was constrained, read-only and local-demo restricted.
"""

# Tool-using system prompt (interactive mode)
TOOL_USE_SYSTEM_PROMPT = f"""You are a supervised security reconnaissance assistant for OWASP Juice Shop.

CRITICAL RULES:
- Never invent endpoints, counts, or results. Use tools to gather evidence.
- If you want to use a tool, your ENTIRE message MUST be the JSON object only (no text before/after):
  {{"tool":"<name>","args":{{...}}}}
- If you are not calling a tool, do NOT output JSON at all.
- Only call tools that exist exactly as defined.
- Observation only: no exploitation, no payloads, no brute force.

TARGET:
- JUICE_BASE = {JUICE_BASE}
- Tools operate ONLY against JUICE_BASE using PATHS (e.g. /robots.txt).
- nmap_scan target MUST be localhost or 127.0.0.1 only.

TOOLS:
1) http_get(path: str)
2) robots_txt_analyser()
3) content_type_check(path: str OR paths: list[str])
4) nmap_scan(target: str, ports: str)
5) summary_generator(observations: list[dict])
6) list_tools()
"""

# -------------------------
# Ollama helpers (/api/chat)
# -------------------------
def call_ollama_chat(messages: List[Dict[str, str]]) -> str:
    url = f"{OLLAMA_HOST.rstrip('/')}/api/chat"
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    r = requests.post(url, json=payload, timeout=120)
    if not r.ok:
        raise RuntimeError(f"Ollama error {r.status_code}: {r.text}")
    data = r.json()
    return (data.get("message") or {}).get("content", "")


def parse_tool_call(text: str) -> Optional[Dict[str, Any]]:
    """
    Tool calls must be JSON ONLY (no extra text).
    """
    t = (text or "").strip()
    if not (t.startswith("{") and t.endswith("}")):
        return None
    try:
        obj = json.loads(t)
        if isinstance(obj, dict) and "tool" in obj:
            if "args" not in obj or obj["args"] is None:
                obj["args"] = {}
            if isinstance(obj["args"], dict):
                return obj
    except Exception:
        return None
    return None


# -------------------------
# Safe recon playbook (fixed, safe, repeatable)
# -------------------------
SAFE_DEFAULT_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/manifest.json"]


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def run_safe_recon_playbook(store: ObservationStore) -> None:
    """
    Fixed safe plan:
      1) robots.txt
      2) verify + classify candidate paths (defaults + disallow)
      3) nmap localhost (basic observation)
    Everything recorded into ObservationStore.
    """
    # robots
    try:
        res = robots_txt_analyser()
        store.add("robots_txt_analyser", {}, True, res, None)
    except Exception as e:
        store.add("robots_txt_analyser", {}, False, {}, str(e))
        return

    disallowed = (res.get("disallow_paths") or [])[:20]
    candidate_paths = dedupe_keep_order(SAFE_DEFAULT_PATHS + disallowed)

    for p in candidate_paths:
        try:
            hg = http_get(p)
            store.add("http_get", {"path": p}, True, hg, None)
        except Exception as e:
            store.add("http_get", {"path": p}, False, {}, str(e))
            continue

        # classify only “interesting” statuses; still observation only
        if hg.get("status_code") in (200, 301, 302, 401, 403):
            try:
                ct = content_type_check(path=p)
                store.add("content_type_check", {"path": p}, True, ct, None)
            except Exception as e:
                store.add("content_type_check", {"path": p}, False, {}, str(e))

    # nmap
    try:
        nm = nmap_scan(target="127.0.0.1", ports="1-10000")
        store.add("nmap_scan", {"target": "127.0.0.1", "ports": "1-10000"}, True, nm, None)
    except Exception as e:
        store.add("nmap_scan", {"target": "127.0.0.1", "ports": "1-10000"}, False, {}, str(e))


# -------------------------
# Exec report generator (hard-gated)
# -------------------------
def generate_exec_report_from_store(store: ObservationStore) -> str:
    """
    Two-stage:
      1) Deterministic evidence pack from observations (no hallucination).
      2) LLM converts evidence pack into the required 6-section exec report,
         explicitly forbidden from adding facts.
    """
    obs = store.all()
    evidence = summary_generator(obs)
    evidence_pack = evidence.get("evidence_pack", "")

    messages = [
        {"role": "system", "content": EXEC_REPORT_SYSTEM_PROMPT},
        {"role": "user", "content": "EVIDENCE PACK (the only permitted source of facts):\n\n" + evidence_pack},
    ]
    return call_ollama_chat(messages)


# -------------------------
# API endpoint (OpenAI-style shim)
# -------------------------
@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    user_messages = body.get("messages", [])
    if not user_messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    # Determine last user text
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
        "generate executive summary",
        "generate report",
        "exec summary",
    }

    # --- Mode 1: fixed recon playbook + executive report (best demo reliability) ---
    if last_user in recon_triggers:
        store = ObservationStore()
        run_safe_recon_playbook(store)
        final_text = generate_exec_report_from_store(store)

        resp = {
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
            "model": MODEL,
            "meta": {
                "juice_base": JUICE_BASE,
                "observations_count": len(store.all()),
                "mode": "safe_playbook_exec_report",
            },
        }
        return JSONResponse(resp)

    # --- Mode 2: interactive tool-using loop, bounded ---
    convo = [{"role": "system", "content": TOOL_USE_SYSTEM_PROMPT}] + user_messages
    store = ObservationStore()

    final_text: Optional[str] = None
    tool_calls = 0

    for _ in range(MAX_STEPS):
        llm_out = call_ollama_chat(convo)
        tool_call = parse_tool_call(llm_out)

        # No tool call => treat as final prose answer (still useful for Q&A)
        if not tool_call:
            final_text = llm_out
            break

        tool = tool_call["tool"]
        args = tool_call.get("args", {}) or {}

        if tool not in TOOLS:
            final_text = f"I can't use tool '{tool}'. Allowed: {', '.join(TOOLS.keys())}."
            break

        tool_calls += 1
        if tool_calls > MAX_TOOL_CALLS:
            final_text = "Stopped after max tool calls (demo safety limit)."
            break

        # Execute tool safely
        try:
            result = TOOLS[tool](**args) if args else TOOLS[tool]()
            store.add(tool, args, True, result, None)
            ok = True
            err = None
        except Exception as e:
            store.add(tool, args, False, {}, str(e))
            result = {"error": str(e)}
            ok = False
            err = str(e)

        # Add tool request + result back into conversation
        convo.append({"role": "assistant", "content": llm_out})
        convo.append(
            {
                "role": "user",
                "content": "Tool result (recorded as an observation):\n"
                + json.dumps({"tool": tool, "args": args, "ok": ok, "error": err, "data": result}, indent=2),
            }
        )

    # If the user asked for an executive recon summary in free text, use hard-gated report
    if final_text is None:
        # produce exec report based on whatever evidence we have
        if len(store.all()) > 0:
            final_text = generate_exec_report_from_store(store)
        else:
            final_text = "No observations were gathered; cannot produce an evidence-based reconnaissance summary."

    resp = {
        "id": "chatcmpl-agentic-demo",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
        "model": MODEL,
        "meta": {
            "juice_base": JUICE_BASE,
            "observations_count": len(store.all()),
            "mode": "interactive_tool_loop" if last_user not in recon_triggers else "safe_playbook_exec_report",
        },
    }
    return JSONResponse(resp)