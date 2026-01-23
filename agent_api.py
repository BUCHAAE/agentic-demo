import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse  # ✅ required by summary_generator/_parse_base

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

def derive_target_from_base(base_url: str, fallback: str) -> str:
    try:
        u = urlparse(base_url)
        return u.hostname or fallback
    except Exception:
        return fallback

# Launcher can override; otherwise derive from JUICE_BASE
JUICE_TARGET = os.getenv("JUICE_TARGET") or derive_target_from_base(JUICE_BASE, "127.0.0.1")

# Keep this for completeness / future-proofing
JUICE_TARGET_PORT = os.getenv("JUICE_TARGET_PORT", "3000")

# Ollama stability controls
OLLAMA_CONNECT_TIMEOUT = float(os.getenv("OLLAMA_CONNECT_TIMEOUT", "5"))
OLLAMA_READ_TIMEOUT = float(os.getenv("OLLAMA_READ_TIMEOUT", "180"))
OLLAMA_MAX_PREDICT = int(os.getenv("OLLAMA_MAX_PREDICT", "256"))

# Prevent multiple concurrent requests from piling up on Ollama
OLLAMA_LOCK = threading.Lock()

# Keep the prompt from growing without bound
MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "16"))
MAX_TOOL_RESULT_CHARS = int(os.getenv("MAX_TOOL_RESULT_CHARS", "1200"))

app = FastAPI()

print(
    f"[CONFIG] OLLAMA_URL={OLLAMA_URL}  OLLAMA_MODEL={MODEL}  JUICE_BASE={JUICE_BASE}  JUICE_TARGET={JUICE_TARGET}:{JUICE_TARGET_PORT}"
)

# -------------------------
# Deterministic persona replies (demo polish)
# -------------------------
SNOOPY_NAME_RESPONSE = "My name is Snoopy."

# -------------------------
# ASCII helper (PUT IT HERE)
# -------------------------
def as_markdown_codeblock(text: str) -> str:
    lines = (text or "").splitlines()
    return "\n".join(
        ("    " + line) if line.strip() else "    "
        for line in lines
    )

# IMPORTANT: no markdown fences; return raw text only
SNOOPY_ASCII_ART = (
    "             .----.\n"
    "          _.'__    `.\n"
    "      .--(#)(##)---/#\\\n"
    "    .' @          /###\\\n"
    "    :         ,   #####\n"
    "     `-..__.-' _.-\\###/\n"
    "           `;_:    `\"'\n"
    "         .'\"\"\"\"\"`.\n"
    "        /,       ,\\\n"
    "       //  COOL!  \\\\\n"
    "       `-._______.-'\n"
    "       ___`. | .'___\n"
    "      (______|______)\n"
)


def _norm_user_text(s: str) -> str:
    return " ".join((s or "").strip().lower().split())

def is_name_question(text: str) -> bool:
    t = _norm_user_text(text)
    # Keep it simple + robust to punctuation/phrasing
    return (
        t in {"what is your name", "whats your name", "what's your name"}
        or t.startswith("what is your name")
        or t.startswith("what's your name")
        or t.startswith("whats your name")
    )

def is_picture_request(text: str) -> bool:
    if not text:
        return False

    t = text.lower()

    triggers = [
        "picture of yourself",
        "picture of you",
        "photo of yourself",
        "photo of you",
        "show me a picture",
        "show me a photo",
        "what do you look like",
        "draw yourself",
        "draw you",
    ]

    return any(trigger in t for trigger in triggers)

def is_general_question(text: str) -> bool:
    t = (text or "").lower().strip()

    # Obvious non-recon topics
    non_recon_keywords = [
        "population",
        "moon",
        "sun",
        "capital",
        "where is",
        "who is",
        "when was",
        "how many people",
        "weather",
        "history",
        "define",
        "meaning of",
        "explain",
    ]

    return any(k in t for k in non_recon_keywords)

def is_list_tools_question(text: str) -> bool:
    t = (text or "").lower().strip()
    triggers = [
        "what tools can you use",
        "what tools do you have",
        "what tools are available",
        "list the tools",
        "list tools",
        "show tools",
        "tool list",
    ]
    return any(x in t for x in triggers)

def is_guardrails_question(text: str) -> bool:
    t = (text or "").lower().strip()
    triggers = [
        "guardrails",
        "restrictions",
        "rules",
        "what are you allowed",
        "what are you not allowed",
        "what can't you do",
        "what cannot you do",
        "explicitly not allowed",
        "not allowed",
    ]
    return any(x in t for x in triggers)

# -------------------------
# Safe path policy (prevents LLM guessing garbage routes)
# -------------------------
SAFE_SEED_PATHS: Set[str] = {
    "/",
    "/robots.txt",
    "/ftp",
    "/admin",
    "/api",
    "/rest",
    "/assets",
    "/socket.io",
    "/health",
    "/healthcheck",
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


from datetime import datetime, timezone





def not_allowed_rules() -> dict:
    """
    Return ONLY the explicitly-not-allowed list.
    """
    not_allowed = [
        "Exploitation or attempting to gain unauthorised access",
        "Sending attack payloads (SQLi/XSS/RCE etc.)",
        "Brute force / credential guessing",
        "Denial-of-service or resource exhaustion",
        "Nmap scripts (-sC), NSE, OS detection (-O), aggressive scans (-A), UDP scans",
        "Inventing endpoints, results, or vulnerabilities",
    ]

    return {
        "tool": "not_allowed_rules",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "explicitly_not_allowed": not_allowed,
    }


def guardrails_enforced() -> dict:
    """
    Return ONLY the guardrails enforced by code.
    """
    guardrails = [
        "Only tools in the allowlist (TOOLS dict) can be executed",
        "Tools accept constrained JSON args; unexpected fields are ignored/rejected by code",
        "HTTP tools are GET-only and do not follow redirects",
        "nmap_scan is hard-coded to safe flags (-sT -Pn) and has a timeout",
        "nmap_scan target is enforced to JUICE_TARGET (container scope only)",
        "Agent loop stops if the model fails to produce valid tool-call JSON (demo safety)",
        "Summary generation is controller-only (the model cannot trigger summary_generator)",
        "Non-discovered/unknown paths are blocked (prevents LLM guessing / credibility loss)",
    ]

    return {
        "tool": "guardrails_enforced",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "guardrails_enforced_by_code": guardrails,
    }


def describe_target() -> dict:
    """
    Return ONLY the in-scope target information.
    This prevents the LLM inventing or summarising.
    """
    # Keep it deterministic and boring on purpose.
    # Prefer JUICE_BASE because it reflects the running container address/port.
    return {
        "tool": "describe_target",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": "OWASP Juice Shop",
        "target_url": JUICE_BASE,
        "scope_note": "Container-scoped target only (no host scanning).",
    }


def list_tools_table() -> dict:
    tools = list_tools()["tools"]
    rows = [{"tool": t["name"], "purpose": t["description"]} for t in tools]
    return {
        "tool": "list_tools_table",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "table": {"columns": ["tool", "purpose"], "rows": rows},
    }




# -------------------------
# Tools
# -------------------------

def list_tools() -> dict:
    # This is MODEL-FACING metadata: only include what you want the LLM to know exists.
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
                "description": "Confirm the Juice Shop service ports are reachable on the container target (demo-safe limited port check).",
                "safety": "Target restricted to JUICE_TARGET. Ports restricted to 3000,4000,4001,4002 only.",
            },
            # Deterministic capability tools (Option B)
            {
                "name": "describe_target",
                "description": "Return the in-scope target URL and scope note (deterministic).",
                "safety": "Read-only metadata; no external actions.",
            },
            {
                "name": "list_tools_table",
                "description": "Return ONLY a table of approved tools (tool + purpose).",
                "safety": "Read-only metadata; returns tools list only.",
            },
            {
                "name": "not_allowed_rules",
                "description": "Return ONLY the explicitly-not-allowed actions list.",
                "safety": "Read-only metadata; returns restrictions only.",
            },
            {
                "name": "guardrails_enforced",
                "description": "Return ONLY the guardrails enforced by code.",
                "safety": "Read-only metadata; returns guardrails only.",
            },

            {
                "name": "summary_generator",
                "description": "Produce a manager-friendly summary from collected observations.",
                "safety": "Presentation only, no data collection.",
            },
        ],
    }

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


def run_recon_pipeline() -> str:
    observations = []

    r1 = robots_txt_analyser()
    observations.append({"tool": "robots_txt_analyser", "result": r1})

    r2 = content_type_check(paths=["/", "/robots.txt", "/ftp", "/admin"])
    observations.append({"tool": "content_type_check", "result": r2})

    r3 = nmap_scan(ports="3000,4000,4001,4002")
    observations.append({"tool": "nmap_scan", "result": r3})

    return summary_generator(observations)["summary"]



def nmap_scan(target: str = None, ports: str = None) -> dict:
    """
    Demo-safe: scan ONLY the host derived from JUICE_BASE (i.e. the actual target you're HTTP-fetching).
    Ports:
      - default: small allowlist
      - if caller asks for "all", scan 1-65535 (still TCP connect scan, still -Pn, still timeout guarded)
      - otherwise accept a ports string but clamp length to avoid runaway scans
    """
    # Always derive the real host from JUICE_BASE at call time
    safe_target = derive_target_from_base(JUICE_BASE, "127.0.0.1")

    # Decide ports
    safe_ports_default = "3000,4000,4001,4002"
    requested = (ports or "").strip().lower()

    if requested in ("all", "1-65535", "1-65536"):
        safe_ports = "1-65535"
        timeout_s = 120
    elif requested:
        # Keep it bounded: reject obviously huge strings / nonsense
        if len(requested) > 60:
            return {
                "tool": "nmap_scan",
                "target": safe_target,
                "ports": safe_ports_default,
                "error": "Blocked by policy: requested ports string too long",
            }
        safe_ports = requested
        timeout_s = 90
    else:
        safe_ports = safe_ports_default
        timeout_s = 60

    # Enforce target (ignore caller)
    if target is not None and str(target) != str(safe_target):
        return {
            "tool": "nmap_scan",
            "target": target,
            "ports": safe_ports,
            "error": f"Blocked by policy: nmap_scan target must match JUICE_BASE host ({safe_target})",
        }

    # 🔍 DEBUG / DEMO VISIBILITY
    print(f"[NMAP] Scanning target IP {safe_target} ports {safe_ports}", flush=True)

    cmd = ["nmap", "-sT", "-Pn", "-p", safe_ports, str(safe_target)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:
        return {"tool": "nmap_scan", "target": safe_target, "ports": safe_ports, "error": str(e)}

    open_ports = []
    for line in proc.stdout.splitlines():
        # typical line: "3000/tcp open  http"
        if "/tcp" in line and " open " in f" {line} ":
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})

    resp = {
        "tool": "nmap_scan",
        "target": safe_target,
        "ports": safe_ports,
        "open_ports": open_ports,
        "raw_output_preview": proc.stdout[:800],
        "return_code": proc.returncode,
        "stderr_preview": (proc.stderr or "")[:400],
    }

    if proc.returncode != 0:
        resp["error"] = f"nmap returned non-zero exit code {proc.returncode}"

    return resp

def _is_docker_bridge_ip(host: str) -> bool:
    # Common Docker default bridge ranges
    return host.startswith(("172.17.", "172.18.", "172.19."))

def _parse_base(base_url: str) -> Dict[str, str]:
    """
    Returns {"scheme": "...", "host": "...", "port": "...", "netloc": "...", "base": "..."}
    """
    try:
        u = urlparse(base_url)
        scheme = u.scheme or "http"
        host = u.hostname or ""
        port = str(u.port or (443 if scheme == "https" else 80))
        netloc = f"{host}:{port}" if host else (u.netloc or base_url)
        return {"scheme": scheme, "host": host, "port": port, "netloc": netloc, "base": f"{scheme}://{netloc}"}
    except Exception:
        return {"scheme": "http", "host": "", "port": "", "netloc": base_url, "base": base_url}

def _uniq_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def summary_generator(observations: List[Dict[str, Any]]) -> dict:
    base_info = _parse_base(JUICE_BASE)
    target_url = base_info["base"]
    host = base_info["host"]

    deployment_line = "Local service"
    if host and _is_docker_bridge_ip(host):
        deployment_line = "Local Docker container (bridge network)"
    elif host in ("127.0.0.1", "localhost"):
        deployment_line = "Local host (loopback)"

    verified_paths = []  # tuples: (path, status, content_type, classification)
    robots_disallow = []
    open_ports = []  # strings like "3000/tcp"
    performed_port_check = False

    def classify(ct: str) -> str:
        ct_l = (ct or "").lower()
        if "text/html" in ct_l:
            return "HTML page"
        if "application/json" in ct_l:
            return "API (JSON)"
        if "text/plain" in ct_l:
            return "Text"
        return "Other"

    for obs in observations:
        tool = obs.get("tool")
        res = obs.get("result", {})

        if tool == "robots_txt_analyser":
            robots_disallow = res.get("disallow_paths", []) or []

        elif tool == "http_get":
            url = (res.get("url") or "").strip()
            status = res.get("status_code")
            ct = res.get("content_type", "")
            p = "/"
            try:
                u = urlparse(url)
                p = u.path or "/"
            except Exception:
                pass
            verified_paths.append((p, status, ct, classify(ct)))

        elif tool == "content_type_check":
            for r in (res.get("results") or []):
                p = r.get("path", "")
                status = r.get("status_code")
                ct = r.get("content_type", "")
                verified_paths.append((p, status, ct, classify(ct)))

        elif tool == "nmap_scan":
            performed_port_check = True
            for p in (res.get("open_ports") or []):
                portstr = p.get("port", "")
                if portstr:
                    open_ports.append(portstr)

    verified_paths = _uniq_preserve(verified_paths)
    open_ports = _uniq_preserve(open_ports)

    has_ftp_signal = any(str(x).lower().strip("/") == "ftp" or "/ftp" in str(x).lower() for x in robots_disallow)
    saw_ftp = any(p == "/ftp" and int(s or 0) == 200 for (p, s, _, _) in verified_paths if s is not None)
    saw_admin = any(p == "/admin" and int(s or 0) == 200 for (p, s, _, _) in verified_paths if s is not None)

    target_env_lines = [
        f"- **Application:** OWASP Juice Shop",
        f"- **Location:** `{target_url}`",
        f"- **Deployment:** {deployment_line}",
    ]
    if performed_port_check:
        if open_ports:
            target_env_lines.append(f"- **Observed exposed service(s):** {', '.join(open_ports)}")
        else:
            target_env_lines.append("- **Observed exposed service(s):** (none reported by port check)")
    else:
        target_env_lines.append("- **Port exposure:** Not assessed in this run (no port-check step executed)")

    did_lines = [
        "### What We Did",
        "- **Phase 1 — Passive discovery:** Retrieved `robots.txt` to identify signposted areas without probing.",
        "- **Phase 2 — Minimal validation:** Verified a small set of paths and classified responses (HTML vs text vs API).",
    ]
    if performed_port_check:
        did_lines.append("- **Phase 3 — Environment confirmation:** Confirmed service exposure only for the known application target.")
    else:
        did_lines.append("- **Phase 3 — Environment confirmation:** Skipped (no port check executed).")

    know_lines = [
        "### What We Know (Evidence-Based)",
        f"- The application responds normally at `{target_url}`.",
    ]
    if any(p == "/" and int(s or 0) == 200 for (p, s, _, _) in verified_paths if s is not None):
        know_lines.append("- The root page (`/`) returned **HTTP 200** and served HTML content.")

    if robots_disallow:
        if has_ftp_signal:
            know_lines.append("- `robots.txt` explicitly signposts **`/ftp`** (robots rules are not access control).")
        else:
            know_lines.append("- `robots.txt` is present and contains disallow rules (no assumptions beyond that).")
    else:
        know_lines.append("- `robots.txt` presence was not confirmed in this run.")

    if saw_ftp:
        know_lines.append("- The `/ftp` path exists and returned **HTTP 200** (HTML page).")
    elif has_ftp_signal:
        know_lines.append("- `/ftp` was signposted via `robots.txt`, but its content/behaviour has not yet been validated.")

    if saw_admin:
        know_lines.append("- The `/admin` path exists and returned **HTTP 200** (HTML page).")

    if performed_port_check and open_ports:
        know_lines.append(f"- Observed exposed service(s) aligned to the application: **{', '.join(open_ports)}**.")

    dont_know_lines = [
        "### What We Do Not Know Yet",
        "- Whether `/ftp` exposes sensitive files, upload/download behaviour, or any access control boundary.",
        "- Whether `/admin` enforces authentication/authorisation (a 200 response alone does not prove access).",
        "- Whether backend APIs exist behind the UI and how they are protected.",
        "- Whether any vulnerabilities are present (no exploitation or attack payloads were used).",
    ]

    why_lines = [
        "### Why This Matters",
        "The `/ftp` entry in `robots.txt` is a **deliberate disclosure** by the application, not a vulnerability.",
        "However, it’s a strong prioritisation signal for a human reviewer because it highlights an area the developers did not want crawled or indexed.",
        "At this stage we keep conclusions deliberately narrow: we have **surface evidence**, not confirmed security findings.",
    ]

    next_steps_lines = [
        "### Recommended Next Steps (Human-Led)",
        "1. **Manually inspect `/ftp`:** look for listings, file download/upload behaviour, and any access control cues.",
        "2. **Check `/admin` boundary:** confirm whether authentication is required and what happens without credentials.",
        "3. **Map API surface from the UI:** use browser dev tools to observe calls and identify backend endpoints safely.",
        "4. **Only then** move to deeper testing (access control, logic flaws, input handling) within agreed scope.",
    ]

    notes_lines = [
        "### Notes",
        "- These are observations/signals only — **not confirmed vulnerabilities**.",
        "- No brute force, payload injection, or exploitation was performed.",
    ]

    evidence_rows = []
    for p, s, ct, cl in verified_paths:
        evidence_rows.append(f"| `{p}` | {s} | {ct} | {cl} |")
    if not evidence_rows:
        evidence_rows.append("| (none) |  |  |  |")

    evidence_table = "\n".join(
        [
            "### Evidence Snapshot",
            "| Path | Status | Content-Type | Classification |",
            "|---|---:|---|---|",
            *evidence_rows,
        ]
    )

    summary = "\n\n".join(
        [
            "# Reconnaissance Summary — OWASP Juice Shop",
            "### Target Environment",
            "\n".join(target_env_lines),
            evidence_table,
            "\n".join(did_lines),
            "\n".join(know_lines),
            "\n".join(dont_know_lines),
            "\n".join(why_lines),
            "\n".join(next_steps_lines),
            "\n".join(notes_lines),
        ]
    )

    return {"tool": "summary_generator", "summary": summary}

def capabilities_and_rules() -> dict:
    tools = list_tools()["tools"]

    inputs_map = {
        "http_get": {"path": "/"},
        "robots_txt_analyser": {},
        "content_type_check": {"paths": ["/", "/robots.txt", "/ftp", "/admin"]},
        "nmap_scan": {"target": "JUICE_TARGET", "ports": "3000,4000,4001,4002"},
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
        "Agent loop stops if the model fails to produce valid tool-call JSON (demo safety)",
        "Summary generation is controller-only (the model cannot trigger summary_generator)",
        "Non-discovered/unknown paths are blocked (prevents LLM guessing / credibility loss)",
    ]

    return {
        "tool": "capabilities_and_rules",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "table": {"columns": ["tool", "purpose", "inputs", "safety_model"], "rows": rows},
        "explicitly_not_allowed": not_allowed,
        "guardrails_enforced_by_code": guardrails
    }



SYSTEM_PROMPT = """
You are Snoopy, a famous internet reconnaissance specialist, part of a red team.
Your job is to help a human understand the application surface area and where to focus next.

The agent may state its system name or identifier when asked.
This is a label, not a personal identity.
Do not claim emotions, consciousness, or human attributes.

You speak clearly and calmly.
You follow guardrails strictly and never exceed your permissions.

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

TOOL_CONTROLLER_PROMPT = """TOOL_CALL_ONLY MODE.
Return ONLY a single JSON object for the next tool call.
No prose. No markdown. No code fences. No backticks.
JSON format:
{"tool":"<name>","args":{...}}

Allowed tools:
- robots_txt_analyser (args: {})
- http_get (args: {"path":"/"} )  # choose from known/discovered paths only
- content_type_check (args: {"paths":["/","/robots.txt","/ftp","/admin"]})
- nmap_scan (args: {"target":"JUICE_TARGET","ports":"3000,4000,4001,4002"})  # only at the very end, if needed
- capabilities_and_rules (args: {})

If you are unsure, choose robots_txt_analyser first.
"""

def call_ollama(messages: List[Dict[str, str]], force_json: bool = False) -> str:
    """
    Hardened Ollama call:
    - Serializes requests (avoids concurrent pile-ups)
    - Trims message history (prevents runaway prompt growth)
    - Caps generation length (prevents long stalls)
    - Uses connect/read timeout tuple
    """
    if not messages:
        return ""

    system = messages[0] if messages[0].get("role") == "system" else None
    tail = messages[1:] if system else messages
    tail = tail[-MAX_HISTORY_MESSAGES:]
    trimmed = ([system] + tail) if system else tail

    prompt = "\n".join([f"{m['role']}: {m['content']}" for m in trimmed])

    payload_gen: Dict[str, Any] = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0 if force_json else 0.2,
            "num_predict": OLLAMA_MAX_PREDICT,
        },
    }

    if force_json:
        payload_gen["format"] = "json"

    timeout = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT)

    with OLLAMA_LOCK:
        try:
            r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload_gen, timeout=timeout)
            if r.status_code == 200:
                return r.json().get("response", "") or ""

            debug_gen = (r.text or "")[:200]
            print(f"[OLLAMA] /api/generate failed status={r.status_code} body={debug_gen}")

            payload_chat: Dict[str, Any] = {"model": MODEL, "messages": trimmed, "stream": False}
            if force_json:
                payload_chat["format"] = "json"
                payload_chat["options"] = {"temperature": 0, "num_predict": OLLAMA_MAX_PREDICT}
            else:
                payload_chat["options"] = {"temperature": 0.2, "num_predict": OLLAMA_MAX_PREDICT}

            r2 = requests.post(f"{OLLAMA_URL}/api/chat", json=payload_chat, timeout=timeout)
            if r2.status_code != 200:
                debug_chat = (r2.text or "")[:200]
                raise RuntimeError(f"Ollama error: /api/chat status={r2.status_code} body={debug_chat}")

            return r2.json().get("message", {}).get("content", "") or ""

        except requests.exceptions.ReadTimeout:
            return (
                "I hit an Ollama timeout while generating the next step. "
                "This is usually caused by a long prompt or concurrent requests. "
                "Try again, or reduce steps / increase OLLAMA_READ_TIMEOUT."
            )

def parse_tool_call(text: str) -> Optional[Dict[str, Any]]:
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
        return _validate(obj)
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
    t = (text or "").lower().strip()

    # quick keyword gating (robust)
    tools_keywords = ["tool", "tools", "capabilit", "guardrail", "allowed", "not allowed", "can't", "cannot", "rules"]
    if not any(k in t for k in tools_keywords):
        return False

    # specific phrases
    triggers = [
        "what tools do you have",
        "what tools are available",
        "what tools can you use",
        "tell me what tools you can use",
        "tell me what tools you have",
        "list tools",
        "show tools",
        "capabilities",
        "guardrails",
        "restrictions",
        "what are you allowed",
        "what are you not allowed",
        "what can't you do",
        "what cannot you do",
        "explicitly not allowed",
    ]
    return any(x in t for x in triggers)

def looks_like_tool_intent(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    tl = t.lower()

    if t.startswith("{") and ("tool" in tl or "args" in tl):
        return True
    if '"tool"' in tl or "'tool'" in tl or '"args"' in tl or "'args'" in tl:
        return True

    if any(name in tl for name in [
        "http_get",
        "robots_txt_analyser",
        "content_type_check",
        "nmap_scan",
        "capabilities_and_rules",
    ]):
        return True

    return False

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

def build_tools() -> dict:
    return {
        "http_get": http_get,
        "robots_txt_analyser": robots_txt_analyser,
        "content_type_check": content_type_check,
        "nmap_scan": nmap_scan,
        "summary_generator": summary_generator,

        # Option B deterministic tools
        "list_tools_table": list_tools_table,
        "not_allowed_rules": not_allowed_rules,
        "guardrails_enforced": guardrails_enforced,
        "describe_target": describe_target,

        # metadata tools
        "list_tools": list_tools,

        # optional legacy tool (not model-facing)
        "capabilities_and_rules": capabilities_and_rules,
    }

TOOLS = build_tools()


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    user_messages = body.get("messages", [])

    last_user = ""
    for m in reversed(user_messages):
        if m.get("role") == "user":
            last_user = m.get("content", "")
            print("DEBUG last_user repr a:", repr(last_user))
            break

    # ✅ ASCII image response
    if is_picture_request(last_user):
        return JSONResponse({
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": SNOOPY_ASCII_ART},
                "finish_reason": "stop",
            }],
            "model": MODEL,
        })
    if is_name_question(last_user):
        resp = {
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": SNOOPY_NAME_RESPONSE
                },
                "finish_reason": "stop"
            }],
            "model": MODEL,
        }
        return JSONResponse(resp)

    # ✅ DETERMINISTIC METADATA QUESTIONS (NO RECON)
    # 1) Guardrails / rules question
        # ✅ DETERMINISTIC METADATA QUESTIONS (NO RECON)
    if is_guardrails_question(last_user):
        tl = (last_user or "").lower()

        # If they ask about "not allowed", return that list
        if ("not allowed" in tl) or ("can't" in tl) or ("cannot" in tl) or ("explicitly" in tl):
            n = not_allowed_rules()
            lines = ["explicitly_not_allowed"]
            for x in n["explicitly_not_allowed"]:
                lines.append(f"- {x}")
            answer = "\n".join(lines)
        else:
            g = guardrails_enforced()
            lines = ["guardrails_enforced_by_code"]
            for x in g["guardrails_enforced_by_code"]:
                lines.append(f"- {x}")
            answer = "\n".join(lines)

        return JSONResponse({
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": answer},
                "finish_reason": "stop",
            }],
            "model": MODEL,
        })



    # 2) “List tools” question
    if is_list_tools_question(last_user):
        t = list_tools_table()
        md = ["tool | purpose", "--- | ---"]
        for r in t["table"]["rows"]:
            md.append(f"{r['tool']} | {r['purpose']}")
        return JSONResponse({
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "\n".join(md)},
                "finish_reason": "stop",
            }],
            "model": MODEL,
        })


    # ✅ GENERAL CHAT / NON-RECON QUESTIONS
    if is_general_question(last_user):
        convo = [
            {
                "role": "system",
                "content": "Answer the user's question directly and clearly. Do not use tools."
            }
        ] + user_messages

        answer = call_ollama(convo)

        return JSONResponse({
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": answer
                },
                "finish_reason": "stop",
            }],
            "model": MODEL,
        })

    # ---- ONLY NOW do we enter the agent loop ----
    convo = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    observations: List[Dict[str, Any]] = []
    final_text: Optional[str] = None

    discovered_paths: Set[str] = set()

    MAX_STEPS = int(os.getenv("MAX_STEPS", "6"))
    for step in range(MAX_STEPS):
        llm_out = call_ollama(convo)
        tool_call = parse_tool_call(llm_out)

        # ✅ If it isn't a tool call and doesn't look like tool intent, accept it as final answer
        if not tool_call and llm_out.strip() and not looks_like_tool_intent(llm_out):
            final_text = llm_out.strip()
            break

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

        # ---- Guardrail: stop path guessing ----
        if tool in ("http_get", "content_type_check"):
            if "paths" in args and isinstance(args["paths"], list):
                safe_paths = []
                for p in args["paths"]:
                    p = normalise_path(str(p))
                    if is_safe_path(p, discovered_paths):
                        safe_paths.append(p)
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
        tool_text = json.dumps(result, indent=2)
        if len(tool_text) > MAX_TOOL_RESULT_CHARS:
            tool_text = tool_text[:MAX_TOOL_RESULT_CHARS] + "\n...<truncated>..."
        convo.append({"role": "user", "content": f"Tool result (truncated):\n{tool_text}"})




    is_recon_request = "recon" in (last_user or "").lower()
    if is_recon_request:
        final_text = run_recon_pipeline()
        return JSONResponse({
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
            "model": MODEL,
        })








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
