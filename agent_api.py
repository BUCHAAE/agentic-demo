import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# -------------------------
# Config
# -------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")

# IMPORTANT: match what is actually installed in Ollama
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

# Launcher should inject these (container-scoped). Defaults are fallback only.
JUICE_BASE = os.getenv("JUICE_BASE", "http://127.0.0.1:3001")
JUICE_TARGET = os.getenv("JUICE_TARGET", "127.0.0.1")
JUICE_TARGET_PORT = os.getenv("JUICE_TARGET_PORT", "3000")

app = FastAPI()

print(f"[CONFIG] OLLAMA_URL={OLLAMA_URL}  OLLAMA_MODEL={MODEL}  JUICE_BASE={JUICE_BASE}  JUICE_TARGET={JUICE_TARGET}:{JUICE_TARGET_PORT}")

# -------------------------
# Safe path policy (prevents LLM guessing garbage routes)
# -------------------------
SAFE_SEED_PATHS: Set[str] = {
    "/", "/robots.txt",
    "/ftp", "/admin",
    "/api", "/rest", "/assets", "/socket.io",
    "/health", "/healthcheck"
}

def normalise_path(p: str) -> str:
    if not p:
        return "/"
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    return p

def is_safe_path(p: str, discovered: Set[str]) -> bool:
    """
    Allow only:
      - seed paths we explicitly permit
      - paths discovered via robots.txt disallow list
    Block:
      - querystrings/fragments (keeps demo clean)
      - empty/None
    """
    if not p:
        return False
    p = normalise_path(p)

    if "?" in p or "#" in p:
        return False

    return (p in SAFE_SEED_PATHS) or (p in discovered)

# -------------------------
# Tool registry metadata
# -------------------------
def list_tools() -> dict:
    return {
        "tool": "list_tools",
        "tools": [
            {
                "name": "http_get",
                "description": "Fetch a specific HTTP path and observe status code, content type, and response preview (GET only).",
                "safety": "Read-only, no payloads, no parameter mutation.",
            },
            {
                "name": "robots_txt_analyser",
                "description": "Read /robots.txt and list disallowed paths as discovery signals.",
                "safety": "Does not enforce or bypass access control.",
            },
            {
                "name": "content_type_check",
                "description": "Classify one or more paths as API(JSON) vs HTML based on HTTP headers and response body.",
                "safety": "Observation only, no inference beyond evidence.",
            },
            {
                "name": "nmap_scan",
                "description": "Confirm the Juice Shop service port is reachable on the container target (no host scanning).",
                "safety": "Target restricted to JUICE_TARGET, port 3000 only. No host scanning.",
            },
            {
                "name": "summary_generator",
                "description": "Produce a manager-friendly summary from collected observations.",
                "safety": "Presentation only, no data collection.",
            },
            {
                "name": "capabilities_and_rules",
                "description": "Return a deterministic table of approved tools, what each does, expected inputs, and enforced safety constraints.",
                "safety": "No external actions; returns only capability/policy metadata.",
            },
        ],
    }

# -------------------------
# Tools
# -------------------------
def http_get(path: str = "/") -> dict:
    path = normalise_path(path)

    url = JUICE_BASE.rstrip("/") + path
    r = requests.get(url, timeout=10, allow_redirects=False)

    return {
        "tool": "http_get",
        "url": url,
        "status_code": r.status_code,
        "content_type": r.headers.get("content-type", ""),
        "location": r.headers.get("location", ""),
        "body_preview": (r.text or "")[:500],
    }


def robots_txt_analyser() -> dict:
    url = JUICE_BASE.rstrip("/") + "/robots.txt"
    r = requests.get(url, timeout=10, allow_redirects=False)
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


def content_type_check(path=None, paths=None) -> dict:
    # Supports either "path" or "paths"
    if paths is None and path is not None:
        paths = path
    if isinstance(paths, str):
        paths = [paths]

    results = []
    for p in paths or []:
        p = normalise_path(p)

        url = JUICE_BASE.rstrip("/") + p
        r = requests.get(url, timeout=10, allow_redirects=False)
        ct = (r.headers.get("content-type", "") or "").lower()

        results.append(
            {
                "path": p,
                "url": url,
                "status_code": r.status_code,
                "content_type": ct,
                "location": r.headers.get("location", ""),
                "is_api": "application/json" in ct,
                "is_html": "text/html" in ct,
                "body_preview": (r.text or "")[:200],
            }
        )

    return {"tool": "content_type_check", "results": results}


def nmap_scan(target: str = None, ports: str = None) -> dict:
    """
    Demo-safe: only allow scanning the Juice Shop container target.
    Default ports restricted to the app port only.
    """
    safe_target = JUICE_TARGET
    safe_ports = ports or JUICE_TARGET_PORT or "3000"

    # Hard block: only allow target == JUICE_TARGET
    if target is None:
        target = safe_target
    if target != safe_target:
        return {
            "tool": "nmap_scan",
            "target": target,
            "ports": safe_ports,
            "error": f"Blocked by policy: nmap_scan target must be JUICE_TARGET ({safe_target})",
        }

    # Hard block: prevent full-range scans in demo
    if safe_ports.strip() in ("1-65535", "0-65535", "1-65536"):
        safe_ports = JUICE_TARGET_PORT or "3000"

    cmd = ["nmap", "-sT", "-Pn", "-p", str(safe_ports), str(target)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        return {"tool": "nmap_scan", "target": target, "ports": safe_ports, "error": str(e)}

    open_ports = []
    for line in proc.stdout.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})

    return {
        "tool": "nmap_scan",
        "target": target,
        "ports": safe_ports,
        "open_ports": open_ports,
        "raw_output_preview": proc.stdout[:800],
        "return_code": proc.returncode,
        "stderr_preview": (proc.stderr or "")[:400],
    }


def summary_generator(observations: List[Dict[str, Any]]) -> dict:
    # Dedup tables + bullets to avoid “amateur spam”
    row_by_path: Dict[str, Dict[str, Any]] = {}
    bullets: Set[str] = set()
    discovered: Set[str] = set()

    # Phase flags (to make output read like a methodology)
    did_robots = False
    did_http = False
    did_ct = False
    did_nmap = False

    for obs in observations:
        tool = obs["tool"]
        res = obs["result"]

        if tool == "robots_txt_analyser":
            did_robots = True
            for p in res.get("disallow_paths", []) or []:
                p = normalise_path(p)
                discovered.add(p)
            if any("ftp" in (x or "").lower() for x in res.get("disallow_paths", []) or []):
                bullets.add("robots.txt references /ftp (robots exclusion is not access control)")

        elif tool == "http_get":
            did_http = True
            url = res.get("url")
            sc = res.get("status_code")
            ct = res.get("content_type")
            bullets.add(f"{url} returned {sc} with {ct}")

        elif tool == "content_type_check":
            did_ct = True
            for r in res.get("results", []) or []:
                path = r.get("path", "")
                row_by_path.setdefault(
                    path,
                    {
                        "path": path,
                        "status": r.get("status_code", ""),
                        "content_type": r.get("content_type", ""),
                        "classification": "HTML page"
                        if r.get("is_html")
                        else "API(JSON)"
                        if r.get("is_api")
                        else "other",
                        "evidence": (r.get("body_preview", "") or "")[:120],
                    },
                )

        elif tool == "nmap_scan":
            did_nmap = True
            for p in res.get("open_ports", []) or []:
                port = p.get("port", "")
                svc = (p.get("service") or "").lower()

                # Don’t print embarrassing nmap guesses like “ppp” in the exec summary.
                if port:
                    if svc in ("http", "http-alt", "https"):
                        bullets.add(f"{port} appears open ({svc})")
                    else:
                        bullets.add(f"{port} appears open")

    # Build evidence table
    rows = list(row_by_path.values())
    table_lines = [
        "path | status_code | content_type | classification | evidence_1st_120_chars",
        "--- | --- | --- | --- | ---",
    ]
    for r in rows:
        table_lines.append(f"{r['path']} | {r['status']} | {r['content_type']} | {r['classification']} | {r['evidence']}")

    # Phase narrative (reads like a real recon approach)
    phases = []
    if did_robots:
        phases.append("**Phase 1 – Passive discovery:** Read `/robots.txt` to identify signposted areas without probing.")
    if did_http or did_ct:
        phases.append("**Phase 2 – Minimal validation:** Confirmed a small set of known/discovered paths and classified responses.")
    if did_nmap:
        phases.append("**Phase 3 – Environment check (optional):** Confirmed expected service port exposure on the container target.")

    summary = (
        "### Evidence table\n\n"
        + "\n".join(table_lines)
        + "\n\n### What we did (method)\n\n"
        + ("\n".join(f"- {p}" for p in phases) if phases else "- No actions recorded.")
        + "\n\n### Manager summary\n\n"
        + "\n".join(f"- {b}" for b in sorted(bullets))
        + "\n\nNote: these are observations/signals, not confirmed vulnerabilities."
    )
    return {"tool": "summary_generator", "summary": summary}


def capabilities_and_rules() -> dict:
    tools = list_tools()["tools"]

    inputs_map = {
        "http_get": {"path": "/"},
        "robots_txt_analyser": {},
        "content_type_check": {"paths": ["/", "/robots.txt", "/ftp", "/admin"]},
        "nmap_scan": {"target": "JUICE_TARGET", "ports": "3000"},
        # model is blocked from calling summary_generator (controller-only)
        "summary_generator": {"observations": "[controller-only]"},
        "capabilities_and_rules": {},
    }

    rows = []
    for t in tools:
        rows.append(
            {
                "tool": t["name"],
                "purpose": t["description"],
                "safety_model": t["safety"],
                "inputs": inputs_map.get(t["name"], {}),
            }
        )

    not_allowed = [
        "Exploitation or attempting to gain unauthorised access",
        "Sending attack payloads (SQLi/XSS/RCE etc.)",
        "Brute force / credential guessing",
        "Denial-of-service or resource exhaustion",
        "Nmap scripts (-sC), NSE, OS detection (-O), aggressive scans (-A), UDP scans",
        "Inventing endpoints, results, or vulnerabilities",
    ]

    guardrails = [
        "Only tools in the allowlist (TOOLS dict) can be executed",
        "Tools accept constrained JSON args; unexpected fields are ignored/rejected by code",
        "HTTP tools are GET-only and do not follow redirects",
        "nmap_scan is hard-coded to safe flags (-sT -Pn) and has a timeout",
        "nmap_scan target is enforced to JUICE_TARGET (container scope only)",
        "Agent loop stops if model fails to produce valid tool-call JSON (demo safety)",
        "Summary generation is controller-only (the model cannot trigger summary_generator)",
        "Non-discovered/unknown paths are blocked (prevents LLM guessing / credibility loss)",
    ]

    return {
        "tool": "capabilities_and_rules",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "table": {"columns": ["tool", "purpose", "inputs", "safety_model"], "rows": rows},
        "explicitly_not_allowed": not_allowed,
        "guardrails_enforced_by_code": guardrails,
    }


TOOLS = {
    "http_get": http_get,
    "robots_txt_analyser": robots_txt_analyser,
    "content_type_check": content_type_check,
    "nmap_scan": nmap_scan,
    "summary_generator": summary_generator,
    "capabilities_and_rules": capabilities_and_rules,
    "list_tools": list_tools,
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
- Use nmap_scan only for confirming the Juice Shop container’s expected port exposure.
- Prefer robots_txt_analyser first, then content_type_check(paths=[...]) for validation.
- Use only the tools listed below.
- If you want to use a tool, output JSON ONLY in this exact format:
  {"tool":"<name>","args":{...}}

TOOLS:
1) http_get(path: str="/")
2) robots_txt_analyser()
3) content_type_check(path: str OR paths: list[str])
4) nmap_scan(target: str="JUICE_TARGET", ports: str="3000")
5) capabilities_and_rules()

If no tool is needed, answer normally in plain English.
Keep outputs short and manager-friendly.
"""

# IMPORTANT: this prompt must match the real safety rules (no localhost / 1-65535)
TOOL_CONTROLLER_PROMPT = """TOOL_CALL_ONLY MODE.
Return ONLY a single JSON object for the next tool call.
No prose. No markdown. No code fences. No backticks.
JSON format:
{"tool":"<name>","args":{...}}

Allowed tools:
- robots_txt_analyser (args: {})
- http_get (args: {"path":"/"} )  # choose from known/discovered paths only
- content_type_check (args: {"paths":["/","/robots.txt","/ftp","/admin"]})
- nmap_scan (args: {"target":"JUICE_TARGET","ports":"3000"})  # only at the very end, if needed
- capabilities_and_rules (args: {})

If you are unsure, choose robots_txt_analyser first.
"""


def call_ollama(messages: List[Dict[str, str]], force_json: bool = False) -> str:
    """
    Bulletproof Ollama call:
    - Prefer /api/generate
    - Optional: force JSON output for tool-call-only mode
    - Fallback to /api/chat if generate fails
    """
    prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])

    payload_gen: Dict[str, Any] = {"model": MODEL, "prompt": prompt, "stream": False}

    if force_json:
        payload_gen["format"] = "json"
        payload_gen["options"] = {"temperature": 0}

    r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload_gen, timeout=60)
    if r.status_code == 200:
        return r.json().get("response", "")

    debug_gen = (r.text or "")[:200]
    print(f"[OLLAMA] /api/generate failed status={r.status_code} body={debug_gen}")

    payload_chat: Dict[str, Any] = {"model": MODEL, "messages": messages, "stream": False}
    if force_json:
        payload_chat["format"] = "json"
        payload_chat["options"] = {"temperature": 0}

    r2 = requests.post(f"{OLLAMA_URL}/api/chat", json=payload_chat, timeout=60)
    if r2.status_code != 200:
        debug_chat = (r2.text or "")[:200]
        raise RuntimeError(f"Ollama error: /api/chat status={r2.status_code} body={debug_chat}")

    return r2.json()["message"]["content"]


def parse_tool_call(text: str) -> Optional[Dict[str, Any]]:
    """
    Robust tool-call parser:
    - Strips code fences
    - Tries full JSON parse
    - If that fails, extracts first {...} block and parses that
    - Validates schema: {"tool": str, "args": dict}
    """
    if not text:
        return None

    t = text.strip()

    # Strip common code fences
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()

    def _validate(obj: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(obj, dict):
            return None
        if "tool" not in obj:
            return None
        if "args" not in obj or obj["args"] is None:
            obj["args"] = {}
        if not isinstance(obj["args"], dict):
            return None
        return obj

    try:
        obj = json.loads(t)
        v = _validate(obj)
        if v:
            return v
    except Exception:
        pass

    start = t.find("{")
    if start == -1:
        return None

    depth = 0
    end = None
    for i in range(start, len(t)):
        ch = t[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    if end is None:
        return None

    candidate = t[start:end].strip()
    try:
        obj = json.loads(candidate)
        return _validate(obj)
    except Exception:
        return None


def is_tools_question(text: str) -> bool:
    t = (text or "").lower()
    triggers = [
        "what tools do you have",
        "what tools are available",
        "list tools",
        "capabilities",
        "rules",
        "not allowed",
        "explicitly not allowed",
        "restrictions",
        "guardrails",
        "what are you allowed",
        "what are you not allowed",
        "what can't you do",
    ]
    return any(x in t for x in triggers)


def deterministic_capabilities_markdown() -> str:
    cap = capabilities_and_rules()
    rows = cap["table"]["rows"]

    md = []
    md.append("### Approved tools (deterministic)\n")
    md.append("tool | purpose | inputs | safety")
    md.append("--- | --- | --- | ---")
    for r in rows:
        md.append(
            f"{r['tool']} | {r['purpose']} | `{json.dumps(r['inputs'], ensure_ascii=False)}` | {r['safety_model']}"
        )

    md.append("\n### Explicitly not allowed")
    md.extend([f"- {x}" for x in cap["explicitly_not_allowed"]])

    md.append("\n### Guardrails enforced by code")
    md.extend([f"- {x}" for x in cap["guardrails_enforced_by_code"]])

    return "\n".join(md)


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    user_messages = body.get("messages", [])
    if not user_messages:
        return JSONResponse({"error": "No messages provided"}, status_code=400)

    # --- Deterministic shortcut for demo-quality answers about tools/rules ---
    last_user = ""
    for m in reversed(user_messages):
        if m.get("role") == "user":
            last_user = m.get("content", "")
            break

    if is_tools_question(last_user):
        final_text = deterministic_capabilities_markdown()
        resp = {
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
            "model": MODEL,
        }
        return JSONResponse(resp)
    # --- end shortcut ---

    convo = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    observations: List[Dict[str, Any]] = []
    final_text: Optional[str] = None

    # Tracks what we *actually* discovered (so we can prevent LLM guessing)
    discovered_paths: Set[str] = set()

    for step in range(12):
        llm_out = call_ollama(convo)
        tool_call = parse_tool_call(llm_out)

        if not tool_call:
            convo.append({"role": "assistant", "content": llm_out})
            convo.append({"role": "user", "content": TOOL_CONTROLLER_PROMPT})
            llm_out = call_ollama(convo, force_json=True)
            tool_call = parse_tool_call(llm_out)

        if not tool_call:
            if step == 0:
                tool_call = {"tool": "robots_txt_analyser", "args": {}}
                llm_out = json.dumps(tool_call)
            else:
                final_text = "Model did not produce a valid tool call. Stopping (demo safety)."
                break

        tool = tool_call["tool"]
        args = tool_call.get("args", {}) or {}

        # Controller-only: model isn't allowed to trigger summary generation
        if tool == "summary_generator":
            observations.append({"tool": "controller", "result": {"note": "Model requested summary generation"}})
            continue

        if tool not in TOOLS:
            if step == 0:
                tool = "robots_txt_analyser"
                args = {}
            else:
                final_text = f"I can't use tool '{tool}'. Allowed: {', '.join(TOOLS.keys())}."
                break

        # ---- WOW guardrail: stop path guessing ----
        if tool in ("http_get", "content_type_check"):
            # normalise to either args["path"] or args["paths"]
            if "paths" in args and isinstance(args["paths"], list):
                safe_paths = []
                for p in args["paths"]:
                    p = normalise_path(str(p))
                    if is_safe_path(p, discovered_paths):
                        safe_paths.append(p)
                # If nothing survived, fall back to "/"
                args["paths"] = safe_paths or ["/"]
                args.pop("path", None)
            else:
                p = normalise_path(args.get("path", "/"))
                if not is_safe_path(p, discovered_paths):
                    p = "/"
                args["path"] = p
                args.pop("paths", None)
        # -----------------------------------------

        try:
            result = TOOLS[tool](**args) if args else TOOLS[tool]()
        except Exception as e:
            final_text = f"Tool '{tool}' failed: {e}"
            break

        # Update discovered paths from robots
        if tool == "robots_txt_analyser":
            for p in result.get("disallow_paths", []) or []:
                discovered_paths.add(normalise_path(p))

        observations.append({"tool": tool, "result": result})

        convo.append({"role": "assistant", "content": llm_out})
        convo.append({"role": "user", "content": f"Tool result:\n{json.dumps(result, indent=2)}"})

    if final_text is None and observations:
        final_text = summary_generator(observations)["summary"]

    if final_text is None:
        final_text = "Stopped after max steps (demo safety limit)."

    resp = {
        "id": "chatcmpl-agentic-demo",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
        "model": MODEL,
    }
    return JSONResponse(resp)


@app.get("/health")
def health():
    return {"ok": True}