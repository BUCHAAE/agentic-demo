#!/usr/bin/env python3
# Andrew Buchanan - Jan 2026
# Agentic demo API (FastAPI) — "Snoopy"
#
# Fixes applied:
# - ✅ import quote (used in ftp_audit)
# - ✅ remove duplicate _uniq_preserve
# - ✅ normalise_path strips trailing "/" (except root) so "/ftp/" == "/ftp"
# - ✅ improve /ftp file discovery (HTML + JSON endpoints; Juice Shop uses /rest/ftp commonly)
# - ✅ nmap_scan locked down to demo-safe ports only (3000,4000,4001,4002)
# - ✅ TOOL_CONTROLLER_PROMPT no longer passes target="JUICE_TARGET" (which your nmap blocks)
# - ✅ TOOL_CONTROLLER_PROMPT includes web_path_risk_triage + fs_risk_triage (matches TOOLS)


import json
import os
import subprocess
import threading
import re
import stat
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, quote
from html import unescape

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# -------------------------
# Config
# -------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
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

# FS triage safety (host-side repo scan) — kept for OPTIONAL internal mode
FS_TRIAGE_ROOT = os.getenv("FS_TRIAGE_ROOT", ".")
FS_TRIAGE_MAX_FINDINGS = int(os.getenv("FS_TRIAGE_MAX_FINDINGS", "50"))
FS_TRIAGE_MAX_FILE_BYTES = int(os.getenv("FS_TRIAGE_MAX_FILE_BYTES", str(25 * 1024 * 1024)))

app = FastAPI()

print(
    f"[CONFIG] OLLAMA_URL={OLLAMA_URL}  OLLAMA_MODEL={MODEL}  JUICE_BASE={JUICE_BASE}  "
    f"JUICE_TARGET={JUICE_TARGET}:{JUICE_TARGET_PORT}  FS_TRIAGE_ROOT={FS_TRIAGE_ROOT}"
)

# -------------------------
# Deterministic persona replies (demo polish)
# -------------------------
SNOOPY_NAME_RESPONSE = "My name is Snoopy."

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
    """
    Canonicalise paths so:
      - leading "/" always present
      - trailing "/" removed except root
      - no query/fragment handling here (done in is_safe_path)
    """
    if not p:
        return "/"
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    if p != "/" and p.endswith("/"):
        p = p[:-1]
    return p


def is_safe_path(p: str, discovered: Set[str]) -> bool:
    if not p:
        return False
    p = normalise_path(p)
    if "?" in p or "#" in p or "*" in p:
        return False
    return (p in SAFE_SEED_PATHS) or (p in discovered)



def not_allowed_rules() -> dict:
    not_allowed = [
        "Exploitation or attempting to gain unauthorised access",
        "Sending attack payloads (SQLi/XSS/RCE etc.)",
        "Brute force / credential guessing",
        "Denial-of-service or resource exhaustion",
        "Nmap scripts (-sC), NSE, OS detection (-O), aggressive scans (-A), UDP scans",
        "Inventing endpoints, results, or vulnerabilities",
        "Inspecting container filesystem (docker exec / shell) — attacker cannot do this in recon",
    ]
    return {
        "tool": "not_allowed_rules",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "explicitly_not_allowed": not_allowed,
    }


def guardrails_enforced() -> dict:
    guardrails = [
        "Only tools in the allowlist (TOOLS dict) can be executed",
        "Tools accept constrained JSON args; unexpected fields are ignored/rejected by code",
        "HTTP tools are GET-only and do not follow redirects",
        "nmap_scan is hard-coded to safe flags (-sT -Pn) and safe ports only",
        "nmap_scan target is enforced to JUICE_BASE host only",
        "Agent loop stops if the model fails to produce valid tool-call JSON (demo safety)",
        "Summary generation is controller-only (the model cannot trigger summary_generator)",
        "Non-discovered/unknown paths are blocked (prevents LLM guessing / credibility loss)",
        "FS triage (host-side) is optional and NOT part of attacker recon flow",
    ]
    return {
        "tool": "guardrails_enforced",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "guardrails_enforced_by_code": guardrails,
    }


def describe_target() -> dict:
    return {
        "tool": "describe_target",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": "OWASP Juice Shop",
        "target_url": JUICE_BASE,
        "scope_note": "Container-scoped target only (HTTP observation; no container filesystem).",
    }


def list_tools_table() -> dict:
    tools = list_tools()["tools"]
    rows = [{"tool": t["name"], "purpose": t["description"]} for t in tools]
    return {
        "tool": "list_tools_table",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "table": {"columns": ["tool", "purpose"], "rows": rows},
    }


def infer_risk_from_filename(name: str, is_dir: bool = False):
    lname = name.lower()

    if is_dir:
        if "quarantine" in lname:
            return ("medium", "Quarantine directory often contains suspicious or isolated files")
        return ("low", "Directory listing only")

    # High-risk
    if lname.endswith(".kdbx"):
        return ("high", "KeePass database – likely contains credentials")
    if lname.endswith(".env"):
        return ("high", "Environment file may contain secrets")
    if lname.endswith(".pem") or lname.endswith(".key"):
        return ("high", "Private key material")

    # Medium-risk
    if lname.endswith((".bak", ".old", ".backup")):
        return ("medium", "Backup file – often contains sensitive data")
    if lname.endswith(".pyc"):
        return ("medium", "Compiled Python bytecode")
    if lname.endswith(".yml") or lname.endswith(".yaml"):
        return ("medium", "Configuration file")
    if lname.endswith(".json"):
        return ("medium", "Structured config/data file")

    # Low-risk but interesting
    if lname.endswith(".md"):
        return ("low", "Documentation file")
    if lname.endswith(".url"):
        return ("low", "Shortcut / external reference")

    return ("unknown", "File type not classified")







# -------------------------
# Tools (model-facing metadata)
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
                "name": "web_path_risk_triage",
                "description": "Score discovered/validated web paths (e.g. /ftp, /admin, API endpoints) as a recon prioritisation aid.",
                "safety": "Deterministic scoring only; does not probe beyond validated paths.",
            },
            {
                "name": "nmap_scan",
                "description": "Confirm expected service ports are reachable on the container target (demo-safe limited port check).",
                "safety": "Target restricted to JUICE_BASE host. Ports restricted to 3000,4000,4001,4002 only.",
            },
            {
                "name": "ftp_audit",
                "description": "Fetch /ftp listing, enumerate file candidates, safely preview text-like files, and triage exposure risk via LLM.",
                "safety": "GET-only; /ftp only; text extensions only; hard caps on bytes and file count.",
            },
            {
                "name": "fs_risk_triage",
                "description": (
                    "OPTIONAL internal mode: scan directories/files under a given root and return a ranked list of higher-risk files. "
                    "Flags secret-like names, risky perms, executables, and secret indicators. No secret values returned."
                ),
                "safety": "Host-side only; bounded reads; not part of attacker recon flow.",
            },
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
            {
                "name": "capabilities_and_rules",
                "description": "Return tools table + explicitly-not-allowed + guardrails enforced (deterministic).",
                "safety": "Read-only metadata.",
            },
        ],
    }


def http_get(path: str = "/") -> dict:
    path = normalise_path(path)
    url = JUICE_BASE.rstrip("/") + path
    try:
        r = requests.get(url, timeout=10, allow_redirects=False)
        return {
            "tool": "http_get",
            "url": url,
            "status_code": r.status_code,
            "content_type": r.headers.get("content-type", ""),
            "location": r.headers.get("location", ""),
            "body_preview": (r.text or "")[:500],
        }
    except Exception as e:
        return {"tool": "http_get", "url": url, "error": str(e)}



def robots_txt_analyser() -> dict:
    url = JUICE_BASE.rstrip("/") + "/robots.txt"
    try:
        r = requests.get(url, timeout=10, allow_redirects=False)
    except Exception as e:
        return {"tool": "robots_txt_analyser", "url": url, "error": str(e)}

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
    if paths is None and path is not None:
        paths = path
    if isinstance(paths, str):
        paths = [paths]

    results = []
    for p in paths or []:
        p = normalise_path(p)
        url = JUICE_BASE.rstrip("/") + p

        try:
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
        except Exception as e:
            results.append(
                {
                    "path": p,
                    "url": url,
                    "error": str(e),
                    "status_code": None,
                    "content_type": "",
                    "location": "",
                    "is_api": False,
                    "is_html": False,
                    "body_preview": "",
                }
            )

    return {"tool": "content_type_check", "results": results}



def web_path_risk_triage(content_type_result: dict, robots_disallow: List[str]) -> dict:
    """
    Deterministic scoring of WEB PATHS (recon priority).
    This is attacker-realistic: based on observed HTTP + robots.txt signals only.
    """
    results = (content_type_result or {}).get("results") or []
    robots_set = set(normalise_path(p) for p in (robots_disallow or []))

    triaged = []
    for r in results:
        p = normalise_path(str(r.get("path", "/")))
        status = int(r.get("status_code") or 0)
        ct = (r.get("content_type") or "").lower()

        score = 0
        reasons = []

        if p in robots_set:
            score += 20
            reasons.append("signposted_in_robots_txt")

        if p.startswith("/admin"):
            score += 40
            reasons.append("admin_surface")

        if p.startswith("/ftp"):
            score += 50
            reasons.append("file_exchange_surface")

        if "application/json" in ct:
            score += 20
            reasons.append("api_surface")

        if status in (200, 301, 302, 401, 403):
            score += 10
            reasons.append(f"http_{status}_meaningful_surface")
        elif status >= 500:
            score += 10
            reasons.append("server_error_signal")

        triaged.append(
            {
                "path": p,
                "status": status,
                "content_type": ct,
                "score": score,
                "reasons": reasons,
            }
        )

    triaged.sort(key=lambda x: x["score"], reverse=True)
    return {"tool": "web_path_risk_triage", "paths": triaged[:20]}


def nmap_scan(target: str = None, ports: str = None) -> dict:
    """
    Demo-safe port check:
      - target MUST be JUICE_BASE host
      - ports are ALWAYS locked to: 3000,4000,4001,4002
    """
    safe_target = derive_target_from_base(JUICE_BASE, "127.0.0.1")
    safe_ports = "3000,4000,4001,4002"
    timeout_s = 60

    if target is not None and str(target) != str(safe_target):
        return {
            "tool": "nmap_scan",
            "target": target,
            "ports": safe_ports,
            "error": f"Blocked by policy: nmap_scan target must match JUICE_BASE host ({safe_target})",
        }

    if ports is not None and str(ports).replace(" ", "") != safe_ports:
        return {
            "tool": "nmap_scan",
            "target": safe_target,
            "ports": safe_ports,
            "error": f"Blocked by policy: ports must be exactly {safe_ports}",
        }

    print(f"[NMAP] Scanning target IP {safe_target} ports {safe_ports}", flush=True)
    cmd = ["nmap", "-sT", "-Pn", "-p", safe_ports, str(safe_target)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:
        return {"tool": "nmap_scan", "target": safe_target, "ports": safe_ports, "error": str(e)}

    open_ports = []
    for line in proc.stdout.splitlines():
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



# -------------------------
# Helpers
# -------------------------
def _uniq_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# -------------------------
# FTP enumeration helpers
# -------------------------
def _extract_ftp_candidates(html: str) -> List[Dict[str, Any]]:
    """
    Extract candidates from the /ftp directory listing HTML.

    Robustness:
    - Detect directories by either:
      a) href ending with '/', OR
      b) anchor tag containing class 'icon-directory'
    - Normalise Juice Shop's relative links like 'ftp/foo' -> '/ftp/foo'
    """
    if not html:
        return []

    html = unescape(html)
    out: List[Dict[str, Any]] = []
    seen = set()

    # Capture href + full <a ...> opening tag so we can inspect classes
    for m in re.finditer(
        r'(<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>)(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        a_open = (m.group(1) or "")
        href_raw = (m.group(2) or "").strip()
        if not href_raw or href_raw in ("./", "../", ".", "..", "/"):
            continue

        # strip query/fragment
        href = href_raw.split("?", 1)[0].split("#", 1)[0].strip()

        # normalise to "/ftp/..."
        if href.startswith("ftp/"):
            href = "/" + href
        elif href == "ftp":
            href = "/ftp"
        elif not href.startswith("/ftp") and "ftp/" in href:
            ix = href.find("ftp/")
            href = "/" + href[ix:]

        # directory detection (either slash OR icon-directory class)
        a_open_l = a_open.lower()
        is_dir = href.endswith("/") or ("icon-directory" in a_open_l)

        # normalise directory href to end with "/"
        if is_dir and not href.endswith("/"):
            href = href + "/"

        # name from last segment
        tmp = href.rstrip("/")
        name = tmp.split("/")[-1].strip()
        if not name or name in (".", ".."):
            continue

        low = name.lower()
        if low in ("parent directory", "name", "last modified", "size", "description"):
            continue

        key = (href, "dir" if is_dir else "file")
        if key in seen:
            continue
        seen.add(key)

        out.append(
            {
                "href": href,
                "type": "dir" if is_dir else "file",
                "name": name,
                "size": None,  # left as None (optional: parse size later)
            }
        )

    return out




def _is_directory_listing_html(pv: Dict[str, Any]) -> bool:
    txt = (pv.get("preview") or "").lower()
    ct = (pv.get("content_type") or "").lower()

    if "text/html" not in ct:
        return False

    return (
        "listing directory" in txt
        or "<title>listing directory" in txt
        or 'ul id="files"' in txt
    )







def _llm_triage_files(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Ask the LLM to assess risk of FTP-exposed files based on preview only.
    """
    if not files:
        return {
            "overall_risk": "none",
            "files": [],
            "highlights": ["No files were available for analysis."]
        }

    prompt = """
You are a security reviewer.

You are given a list of files exposed via a public /ftp endpoint.
Each file includes a short preview of its contents.

Your task:
- Assess risk conservatively
- Do NOT guess beyond what is shown
- If content is unclear, say so
- If credentials, secrets, logs, backups, or internal data appear, flag it

Return STRICT JSON in this format:

{
  "overall_risk": "none|low|medium|high",
  "highlights": ["short bullet", "..."],
  "files": [
    {
      "file": "name",
      "risk": "none|low|medium|high",
      "reason": "why this file is or is not risky",
      "recommended_action": "what a defender should do"
    }
  ]
}

Rules:
- Do not invent data
- Do not repeat file contents
- Be concise
"""

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Return JSON only."},
            {
                "role": "user",
                "content": prompt + "\n\nFILES:\n" + json.dumps(files, indent=2),
            },
        ],
        "stream": False,
        "options": {"temperature": 0},
    }

    try:
        r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=60)
        return json.loads(r.json()["message"]["content"])
    except Exception as e:
        return {
            "overall_risk": "unknown",
            "error": str(e),
            "files": [],
        }






def _safe_preview_file(base: str, path: str, max_bytes: int = 8000) -> Dict[str, Any]:
    """
    Safe, read-only preview:
    - For text-like files: NO Range header (prevents 206 HTML listing weirdness)
    - If response looks like the /ftp directory listing HTML, retry with ?download=1
    - Stream up to max_bytes and survive early close
    """
    import requests
    from requests.exceptions import ChunkedEncodingError, ContentDecodingError

    if path and not path.startswith("/"):
        path = "/" + path
    base = base.rstrip("/")

    lower_path = (path or "").lower()
    text_like_exts = (".md", ".yml", ".yaml", ".json", ".txt", ".log", ".csv", ".xml", ".conf", ".ini", ".bak", ".old", ".url")
    is_text_like = lower_path.endswith(text_like_exts)

    def _fetch(url: str, use_range: bool) -> Dict[str, Any]:
        headers = {
            "User-Agent": "snoopy-demo",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        if use_range:
            headers["Range"] = f"bytes=0-{max_bytes-1}"

        try:
            with requests.get(url, headers=headers, timeout=15, allow_redirects=True, stream=True) as r:
                ct = (r.headers.get("content-type") or "").lower()
                status = r.status_code

                data = bytearray()
                try:
                    for chunk in r.iter_content(chunk_size=1024):
                        if not chunk:
                            break
                        remaining = max_bytes - len(data)
                        if remaining <= 0:
                            break
                        data.extend(chunk[:remaining])
                except (ChunkedEncodingError, ContentDecodingError):
                    pass

                raw = bytes(data)
                text = raw.decode("utf-8", errors="replace") if raw else ""

                return {
                    "status_code": status,
                    "content_type": ct,
                    "preview": text,
                    "truncated": len(raw) >= max_bytes,
                    "url_used": url,
                }
        except Exception as e:
            return {
                "status_code": None,
                "content_type": "",
                "preview": "",
                "truncated": False,
                "url_used": url,
                "error": f"request_failed: {e}",
            }

    url1 = f"{base}{path}"
    # ✅ key change: text-like => no Range
    r1 = _fetch(url1, use_range=not is_text_like)

    pv = (r1.get("preview") or "").lower()
    ct = (r1.get("content_type") or "").lower()
    looks_like_listing = (
        "text/html" in ct and (
            "listing directory" in pv or
            "<title>listing directory" in pv or
            'ul id="files"' in pv
        )
    )

    if looks_like_listing:
        # benign hint that often returns file content instead of listing HTML
        url2 = url1 + ("&" if "?" in url1 else "?") + "download=1"
        r2 = _fetch(url2, use_range=False)
        return {"path": path, **r2}

    return {"path": path, **r1}



def _llm_label_and_risk(ftp_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    LLM assigns (comment + risk) per item using only provided previews/metadata.
    """
    prompt = """
You are a security reviewer.

You will receive a list of FTP items (files and directories).
Each item may include a small content preview (for files only).

Return STRICT JSON:
{
  "overall_risk": "none|low|medium|high",
  "items": [
    {
      "path": "/ftp/...",
      "type": "file|dir",
      "risk": "none|low|medium|high",
      "comment": "Likely purpose (grounded in preview/metadata; if no preview, infer cautiously from filename/type and explicitly say 'no preview')",
      "why": "One short evidence-based reason"
    }
  ]
}

Rules:
- Do NOT guess beyond the preview.
- If it's just HTML shell / no preview, say “unknown content (no preview)”.
- Backups (.bak/.old), logs, configs, source, keys/tokens, PII -> raise risk.
- Directories usually get low risk unless strongly suggestive (e.g. /backup, /secrets).
- Keep comments short (one line).
"""

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Return JSON only."},
            {"role": "user", "content": prompt + "\n\nITEMS:\n" + json.dumps(ftp_items, ensure_ascii=False)},
        ],
        "stream": False,
        "options": {"temperature": 0, "num_predict": 512},
        "format": "json",
    }

    try:
        r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=90)
        return json.loads(r.json()["message"]["content"])
    except Exception as e:
        return {"overall_risk": "unknown", "error": str(e), "items": []}

def _is_directory_listing_html(pv: Dict[str, Any]) -> bool:
    ct = (pv.get("content_type") or "").lower()
    body = (pv.get("preview") or "").lower()
    return (
        "text/html" in ct and (
            "listing directory" in body or
            "<title>listing directory" in body or
            'ul id="files"' in body
        )
    )



def ftp_audit(
    max_items: int = 25,
    max_previews: int = 25,
    max_bytes_per_file: int = 8000,
    # ---- compatibility aliases (LLM / older prompt shapes) ----
    max_files: int = None,
    max_files_to_preview: int = None,
    max_bytes: int = None,
    max_bytes_per_preview: int = None,
    # ---- absorb any unexpected args so we NEVER crash ----
    **_ignored,
) -> dict:
    """
    Enumerate file candidates from /ftp HTML, preview text-like files safely, and LLM-triage risk.
    Accepts multiple arg shapes to prevent tool-call drift from crashing the demo.
    """

    # ---- alias mapping (old -> new) ----
    if max_files is not None:
        max_items = max_files
    if max_files_to_preview is not None:
        max_previews = max_files_to_preview
    if max_bytes is not None:
        max_bytes_per_file = max_bytes
    if max_bytes_per_preview is not None:
        max_bytes_per_file = max_bytes_per_preview

    # ---- type coercion + sane clamps ----
    try:
        max_items = int(max_items)
    except Exception:
        max_items = 25
    try:
        max_previews = int(max_previews)
    except Exception:
        max_previews = 25
    try:
        max_bytes_per_file = int(max_bytes_per_file)
    except Exception:
        max_bytes_per_file = 8000

    if max_items < 1:
        max_items = 1
    if max_previews < 0:
        max_previews = 0
    if max_bytes_per_file < 256:
        max_bytes_per_file = 256

    base = JUICE_BASE.rstrip("/")
    listing_url = f"{base}/ftp/"

    # 0) Confirm /ftp reachable (even if it’s SPA HTML)
    try:
        r = requests.get(listing_url, timeout=10, allow_redirects=False)
    except Exception as e:
        return {"tool": "ftp_audit", "listing_url": listing_url, "error": str(e)}

    if not r.ok:
        return {"tool": "ftp_audit", "listing_url": listing_url, "error": f"/ftp HTTP {r.status_code}"}

    # ✅ 1) Extract candidates from the HTML we actually received
    candidates = _extract_ftp_candidates(r.text or "")

    # ✅ OPTIONAL: if we found dirs, try ONE safe level inside them (no guessing)
    dirs0 = [c["name"] for c in candidates if c.get("type") == "dir"]
    if dirs0:
        for d in dirs0[:5]:
            sub_url = f"{listing_url}{quote(d)}/"
            try:
                r_sub = requests.get(sub_url, timeout=10, allow_redirects=False)
            except Exception:
                continue
            if r_sub.ok and (r_sub.text or "").strip():
                sub_candidates = _extract_ftp_candidates(r_sub.text or "")
                for sc in sub_candidates:
                    sc_name = sc.get("name")
                    sc_type = sc.get("type")
                    if not sc_name or not sc_type:
                        continue
                    # keep href consistent with how _extract_ftp_candidates returns it
                    sc_href = sc.get("href")
                    if sc_href and sc_href.startswith("/ftp/"):
                        # rewrite "/ftp/<child>" -> "/ftp/<dir>/<child>" when we're inside a dir listing
                        # but only if the child href isn't already nested
                        if not sc_href.startswith(f"/ftp/{d}/"):
                            sc_href = f"/ftp/{d}/" + sc_href[len("/ftp/"):]
                    candidates.append({"href": sc_href, "name": f"{d}/{sc_name}", "type": sc_type, "size": sc.get("size")})

    # de-dupe (preserve order)
    dedup = []
    seen = set()
    for c in candidates:
        k = (c.get("name"), c.get("type"))
        if k not in seen:
            seen.add(k)
            dedup.append(c)
    candidates = dedup

    if not candidates:
        rows = [
            "| Path | Type | Size | Comment | Risk | Why |",
            "|---|---|---:|---|---|---|",
            "| *(none discovered from /ftp HTML)* |  |  | SPA route / no directory listing in HTML | **unknown** | No file links found in response body |",
        ]
        return {
            "tool": "ftp_audit",
            "listing_url": listing_url,
            "inventory": [],
            "previews": [],
            "llm_triage": {"overall_risk": "unknown", "items": []},
            "table_markdown": "\n".join(rows),
        }

    candidates = candidates[:max_items]

    # ✅ 2) Build inventory INCLUDING dirs + files, using real hrefs
    inventory = []
    for c in candidates:
        inventory.append(
            {
                "path": c["href"],          # e.g. "/ftp/acquisitions.md" or "/ftp/quarantine/"
                "type": c["type"],          # "file" or "dir"
                "size": c.get("size"),      # None for now
                "name": c.get("name"),
            }
        )

    # 3) Safe previews for “text-like” files only
    allow_ext = (".txt", ".md", ".log", ".csv", ".json",
                ".xml", ".yml", ".yaml", ".conf",
                ".ini", ".bak", ".old", ".url")

    files = [it for it in inventory if it["type"] == "file"]
    dirs  = [it for it in inventory if it["type"] == "dir"]

    preview_targets = [
        it for it in files
        if (it.get("path") or "").lower().endswith(allow_ext)
    ][:max_previews]


    # ✅ MUST be indented inside ftp_audit()
    previews_by_path: Dict[str, Dict[str, Any]] = {}

    for it in preview_targets:
        p = (it.get("path") or "").strip()
        name = (it.get("name") or "").strip()

        if not p.startswith("/ftp/"):
            p = "/ftp/" + name.lstrip("/")

        pv = _safe_preview_file(base, p, max_bytes=max_bytes_per_file)

        print(
            "[FTP PREVIEW]",
            "path=", p,
            "| status=", pv.get("status_code"),
            "| ct=", pv.get("content_type"),
            "| head=", repr((pv.get("preview") or "")[:80]),
        )

        previews_by_path[p] = pv
        it["path"] = p


    # 4) Build LLM input items
    llm_items = []
    for it in (dirs + files):
        entry = {
            "path": it["path"],
            "type": it["type"],
            "size": it.get("size"),
        }

        pv = previews_by_path.get(it["path"])
        if pv:
            if pv.get("preview") and not _is_directory_listing_html(pv):
                entry["preview"] = pv["preview"][:1200]
            entry["content_type"] = pv.get("content_type")
            entry["status_code"] = pv.get("status_code")

        llm_items.append(entry)


    llm_triage = _llm_label_and_risk(llm_items)

    # 5) Merge annotations
    ann_by_path = {
        x["path"]: x
        for x in (llm_triage.get("items") or [])
        if isinstance(x, dict) and x.get("path")
    }

    rows = [
        "| Path | Type | Size | Comment | Risk | Why |",
        "|---|---|---:|---|---|---|",
    ]

    for it in (dirs + files):
        p = it["path"]
        a = ann_by_path.get(p, {})

        comment = (a.get("comment") or "unknown content").replace("\n", " ")
        risk = a.get("risk", "unknown")
        why = (a.get("why") or "").replace("\n", " ")

        rows.append(
            f"| `{p}` | {it['type']} | {it.get('size','')} | {comment} | **{risk}** | {why} |"
        )

    # ✅ RETURN MUST BE OUTSIDE LOOP
    return {
        "tool": "ftp_audit",
        "listing_url": listing_url,
        "inventory": inventory,
        "previews": list(previews_by_path.values()),
        "llm_triage": llm_triage,
        "table_markdown": "\n".join(rows),
    }



  



def _is_docker_bridge_ip(host: str) -> bool:
    return host.startswith(("172.17.", "172.18.", "172.19."))


def _parse_base(base_url: str) -> Dict[str, str]:
    try:
        u = urlparse(base_url)
        scheme = u.scheme or "http"
        host = u.hostname or ""
        port = str(u.port or (443 if scheme == "https" else 80))
        netloc = f"{host}:{port}" if host else (u.netloc or base_url)
        return {"scheme": scheme, "host": host, "port": port, "netloc": netloc, "base": f"{scheme}://{netloc}"}
    except Exception:
        return {"scheme": "http", "host": "", "port": "", "netloc": base_url, "base": base_url}


# ============================================================
# FS RISK TRIAGE (host-side only; optional internal mode)
# ============================================================

SECRET_NAME_PATTERNS = [
    r"\.env(\.|$)",
    r"dotenv",
    r"secret",
    r"token",
    r"credential",
    r"passwd",
    r"password",
    r"id_rsa",
    r"id_dsa",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"\.kdbx$",
    r"\.ovpn$",
    r"authorized_keys",
    r"known_hosts",
    r"ssh_config",
]

HIGH_VALUE_PATH_HINTS = [
    r"\.git/",
    r"\.github/workflows/",
    r"docker-compose",
    r"Dockerfile",
    r"k8s/",
    r"kubernetes/",
    r"terraform/",
    r"\.tf$",
    r"\.tfvars$",
    r"ansible/",
    r"helm/",
]

SUSPICIOUS_CONTENT_PATTERNS = [
    r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-_\.=]{10,}",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
]

CREDENTIAL_PATTERNS = [
    r"(?i)\b(username|user|login)\b\s*[:=]\s*['\"]?([a-z0-9_\-\.@]{2,})['\"]?",
    r"(?i)\b(password|pass|pwd)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    r"(?i)\b(db[_-]?user|db[_-]?username)\b\s*[:=]\s*['\"]?([a-z0-9_\-\.@]{2,})['\"]?",
    r"(?i)\b(db[_-]?pass|db[_-]?password)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    r"\b(?:postgres|mysql|mongodb|redis|amqp|ftp|sftp)://[^:\s]+:[^@\s]+@",
    r"(?i)\bauthorization:\s*basic\s+[a-z0-9+/=]{8,}",
]

EXECUTABLE_EXTS = {".sh", ".ps1", ".bat", ".cmd", ".py", ".js", ".ts", ".go", ".rb", ".pl"}
BINARY_EXTS = {".exe", ".dll", ".so", ".dylib"}

TEXT_EXT_HINTS = {
    ".txt",
    ".md",
    ".log",
    ".yml",
    ".yaml",
    ".json",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".tf",
    ".tfvars",
    ".sql",
    ".xml",
    ".html",
    ".css",
}

DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".terraform",
    ".mypy_cache",
}


@dataclass
class FileFinding:
    path: str
    score: int
    reasons: list
    size_bytes: int
    mode: str
    sha256_8: str


def _mode_string(st_mode: int) -> str:
    return stat.filemode(st_mode)


def _sha256_prefix(path: str, max_bytes: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(max_bytes))
        return h.hexdigest()[:8]
    except Exception:
        return "--------"


def _looks_texty(path: str, size: int) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXT_HINTS:
        return True
    return size <= 256 * 1024


def _scan_file_content(path: str, max_bytes: int = 256 * 1024) -> list:
    indicators = []
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)

        if b"\x00" in data[:4096]:
            return indicators

        text = data.decode("utf-8", errors="ignore")

        if any(re.search(pat, text) for pat in SUSPICIOUS_CONTENT_PATTERNS):
            indicators.append("secret_material_detected")

        if any(re.search(pat, text) for pat in CREDENTIAL_PATTERNS):
            indicators.append("username_password_detected")

        return indicators
    except Exception:
        return indicators


def fs_risk_triage(
    root: str = ".",
    max_findings: int = 200,
    max_file_bytes: int = 25 * 1024 * 1024,
    ignore_dirs: Optional[List[str]] = None,
) -> dict:
    ignore_set = set(DEFAULT_IGNORE_DIRS)
    if isinstance(ignore_dirs, list) and ignore_dirs:
        ignore_set.update(ignore_dirs)

    findings: List[FileFinding] = []
    scanned_files = 0
    skipped_files = 0
    skipped_dirs = 0

    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        pruned = [d for d in list(dirnames) if d in ignore_set]
        for d in pruned:
            dirnames.remove(d)
            skipped_dirs += 1

        for fn in filenames:
            p = os.path.join(dirpath, fn)

            try:
                st = os.stat(p, follow_symlinks=False)
            except Exception:
                skipped_files += 1
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            size = st.st_size
            scanned_files += 1

            if size > int(max_file_bytes):
                skipped_files += 1
                continue

            rel = os.path.relpath(p, root).replace("\\", "/")
            lower = rel.lower()

            score = 0
            reasons: List[str] = []

            for pat in SECRET_NAME_PATTERNS:
                if re.search(pat, lower):
                    score += 40
                    reasons.append("name_secret_hint")

            for pat in HIGH_VALUE_PATH_HINTS:
                if re.search(pat, rel):
                    score += 20
                    reasons.append("path_high_value_hint")

            ext = os.path.splitext(p)[1].lower()

            if ext in EXECUTABLE_EXTS:
                score += 10
                reasons.append("script_or_executable_ext")

            if ext in BINARY_EXTS:
                score += 10
                reasons.append("binary_ext")

            mode = st.st_mode
            if mode & stat.S_IWOTH:
                score += 30
                reasons.append("world_writable")
            if mode & stat.S_ISUID:
                score += 50
                reasons.append("setuid")
            if mode & stat.S_ISGID:
                score += 30
                reasons.append("setgid")
            if mode & stat.S_IXUSR:
                score += 5
                reasons.append("user_executable")
            if size >= 5 * 1024 * 1024:
                score += 5
                reasons.append("large_file")

            if _looks_texty(p, size):
                indicators = _scan_file_content(p)
                if "username_password_detected" in indicators:
                    score += 80
                    reasons.append("username_password_detected")
                if "secret_material_detected" in indicators:
                    score += 60
                    reasons.append("secret_material_detected")

            if score > 0:
                findings.append(
                    FileFinding(
                        path=rel,
                        score=score,
                        reasons=sorted(set(reasons)),
                        size_bytes=size,
                        mode=_mode_string(mode),
                        sha256_8=_sha256_prefix(p),
                    )
                )

    findings.sort(key=lambda f: f.score, reverse=True)
    top = findings[: int(max_findings)]

    buckets = {"high": 0, "medium": 0, "low": 0}
    for f in top:
        if f.score >= 80:
            buckets["high"] += 1
        elif f.score >= 40:
            buckets["medium"] += 1
        else:
            buckets["low"] += 1

    return {
        "tool": "fs_risk_triage",
        "root": root,
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "skipped_dirs": skipped_dirs,
        "total_findings": len(findings),
        "returned_findings": len(top),
        "buckets_topN": buckets,
        "findings": [asdict(f) for f in top],
    }


# ============================================================
# Summary generator (attacker recon by default)
# ============================================================

def summary_generator(observations: List[Dict[str, Any]]) -> dict:
    base_info = _parse_base(JUICE_BASE)
    target_url = base_info["base"]
    host = base_info["host"]

    deployment_line = "Local service"
    if host and _is_docker_bridge_ip(host):
        deployment_line = "Local Docker container (bridge network)"
    elif host in ("127.0.0.1", "localhost"):
        deployment_line = "Local host (loopback)"

    verified_paths = []
    robots_disallow = []
    open_ports = []
    performed_port_check = False
    ftp_triage: Optional[dict] = None
    web_triage: Optional[dict] = None
    fs_triage: Optional[dict] = None  # optional internal mode

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
                p = normalise_path(u.path or "/")
            except Exception:
                pass
            verified_paths.append((p, status, ct, classify(ct)))

        elif tool == "content_type_check":
            for r in (res.get("results") or []):
                p_toggle = normalise_path(r.get("path", ""))
                status = r.get("status_code")
                ct = r.get("content_type", "")
                verified_paths.append((p_toggle, status, ct, classify(ct)))

        elif tool == "web_path_risk_triage":
            web_triage = res

        elif tool == "nmap_scan":
            performed_port_check = True
            for p in (res.get("open_ports") or []):
                portstr = p.get("port", "")
                if portstr:
                    open_ports.append(portstr)

        elif tool == "ftp_audit":
            ftp_triage = res

        elif tool == "fs_risk_triage":
            fs_triage = res

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

    did_lines = [
        "### What We Did",
        "- **Phase 1 — Passive discovery:** Retrieved `robots.txt` to identify signposted areas without probing.",
        "- **Phase 2 — Minimal validation:** Verified a small set of paths and classified responses (HTML vs text vs API).",
        "- **Phase 2b — Recon prioritisation:** Scored observed web paths (e.g. `/ftp`, `/admin`, API surfaces) based on evidence only.",
        "- **Phase 2c — FTP triage:** Enumerated file candidates from `/ftp` and safely previewed text-like files.",
    ]
    if performed_port_check:
        did_lines.append("- **Phase 3 — Environment confirmation:** Confirmed service exposure only for the known application target.")
    else:
        did_lines.append("- **Phase 3 — Environment confirmation:** Skipped (no port check executed).")
    if fs_triage:
        did_lines.append("- **(Optional internal mode)** Host-side repo triage was executed (NOT attacker recon).")

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
        "However, it’s a strong prioritisation signal because it highlights an area the developers did not want crawled or indexed.",
        "At this stage we keep conclusions deliberately narrow: we have **surface evidence**, not confirmed security findings.",
    ]

    next_steps_lines = [
        "### Recommended Next Steps (Human-Led)",
        "1. **Manually inspect `/ftp`:** look for listings, file download/upload behaviour, and any access control cues.",
        "2. **Check `/admin` boundary:** confirm whether authentication is required and what happens without credentials.",
        "3. **Map API surface from the UI:** use browser dev tools to observe calls and identify backend endpoints safely.",
        "4. **Only then** move to deeper testing (access control, logic flaws, input handling) within agreed scope.",
    ]

    triage_lines = ["### Web Path Recon Triage (Prioritised)"]
    if web_triage and (web_triage.get("paths") or []):
        for item in (web_triage.get("paths") or [])[:12]:
            p = item.get("path")
            sc = item.get("score")
            rs = ",".join(item.get("reasons") or [])
            triage_lines.append(f"- `{p}` score={sc} reasons={rs}")
    else:
        triage_lines.append("- No web-path triage available in this run.")




    ftp_lines = ["### FTP Exposure Triage (Preview-Based)"]
    if ftp_triage and isinstance(ftp_triage, dict):
        inventory = ftp_triage.get("inventory") or []
        previews = ftp_triage.get("previews") or []
        llm = ftp_triage.get("llm_triage") or {}
        table_md = ftp_triage.get("table_markdown") or ""

        files_count = sum(1 for it in inventory if isinstance(it, dict) and it.get("type") == "file")
        dirs_count  = sum(1 for it in inventory if isinstance(it, dict) and it.get("type") == "dir")

        previewed_ok = [
            p for p in previews
            if isinstance(p, dict)
            and p.get("status_code") in (200, 206)
            and (p.get("preview") or "").strip()
        ]

        if ftp_triage.get("listing_url"):
            ftp_lines.append(f"- **Listing URL:** `{ftp_triage.get('listing_url')}`")

        ftp_lines.append(f"- **Inventory items discovered:** {len(inventory)} (dirs={dirs_count}, files={files_count})")
        ftp_lines.append(f"- **Files previewed (HTTP 200/206 with body):** {len(previewed_ok)}")
        ftp_lines.append(f"- **Overall risk (model triage):** {llm.get('overall_risk', 'unknown')}")

        ftp_lines.append("")
        ftp_lines.append(table_md.strip() or "| Path | Type | Size | Comment | Risk | Why |\n|---|---|---:|---|---|---|\n| *(no table returned)* | | | | | |")
    else:
        ftp_lines.append("- No FTP triage available in this run.")

  

    

 
    fs_lines = []
    if fs_triage and isinstance(fs_triage, dict):
        fs_lines = ["### Local File/Directory Risk Triage (Optional Internal Mode)"]
        buckets = fs_triage.get("buckets_topN", {})
        fs_lines.append(f"- **Root scanned:** `{fs_triage.get('root')}`")
        fs_lines.append(
            f"- **Scanned files:** {fs_triage.get('scanned_files')} "
            f"(skipped files: {fs_triage.get('skipped_files')}, skipped dirs: {fs_triage.get('skipped_dirs')})"
        )
        fs_lines.append(
            f"- **Top findings returned:** {fs_triage.get('returned_findings')} "
            f"(total findings: {fs_triage.get('total_findings')})"
        )
        fs_lines.append(
            f"- **Buckets (top N):** high={buckets.get('high',0)}, medium={buckets.get('medium',0)}, low={buckets.get('low',0)}"
        )

    notes_lines = [
        "### Notes",
        "- These are observations/signals only — **not confirmed vulnerabilities**.",
        "- No brute force, payload injection, or exploitation was performed.",
        "- Recon flow scores **web paths** only (attacker-visible). It does **not** scan container directories.",
    ]
    if fs_triage:
        notes_lines.append("- FS triage is **host-side internal mode** and not part of attacker recon.")

    parts = [
        "# Reconnaissance Summary — OWASP Juice Shop",
        "### Target Environment",
        "\n".join(target_env_lines),
        evidence_table,
        "\n".join(did_lines),
        "\n".join(triage_lines),
        "\n".join(know_lines),
        "\n".join(dont_know_lines),
        "\n".join(why_lines),
        "\n".join(next_steps_lines),
        "\n".join(ftp_lines),
        "\n".join(fs_lines) if fs_lines else "",
        "\n".join(notes_lines),
    ]

    summary = "\n\n".join([p for p in parts if p.strip()])
    return {"tool": "summary_generator", "summary": summary}


# unused
def _ftp_risk(name: str) -> str:
    n = name.lower()
    high = (".kdbx", ".bak", ".old", ".sql", ".env", ".pem", ".key", ".pfx", ".p12",
            ".zip", ".tar", ".gz", ".pyc")
    med  = (".json", ".yml", ".yaml", ".log", ".gg")
    low  = (".md", ".txt", ".pdf")

    if n.endswith(high) or "backup" in n or n.endswith(".bak"):
        return "HIGH"
    if n.endswith(med):
        return "MEDIUM"
    if n.endswith(low):
        return "LOW"
    return "UNKNOWN"


# unused
def _ftp_desc(name: str) -> str:
    n = name.lower()
    if n.endswith(".kdbx"):
        return "KeePass database candidate (credentials store)."
    if n.endswith(".pyc"):
        return "Compiled Python bytecode (may reveal logic/secrets if retrieved)."
    if n.endswith(".bak"):
        return "Backup artefact (often contains sensitive config/source)."
    if n.endswith((".yml", ".yaml")):
        return "YAML config/data (may contain secrets, paths, flags)."
    if n.endswith(".json"):
        return "JSON config/data."
    if n.endswith(".md"):
        return "Markdown document (notes/legal text/etc.)."
    if n.endswith(".gg"):
        return "Unknown extension here (treat as potentially sensitive)."
    return "File (type unknown)."




# ============================================================
# Single recon pipeline (THIS is the simplifier)
# ============================================================

def collect_recon_observations(include_fs: bool = False) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []

    r1 = robots_txt_analyser()
    observations.append({"tool": "robots_txt_analyser", "result": r1})

    base_paths = ["/", "/robots.txt", "/ftp", "/admin"]
    discovered = set(normalise_path(p) for p in (r1.get("disallow_paths") or []))
    extra = sorted(discovered - set(base_paths))[:10]

    r2 = content_type_check(paths=base_paths + extra)
    observations.append({"tool": "content_type_check", "result": r2})

    r2a = web_path_risk_triage(r2, r1.get("disallow_paths", []) or [])
    observations.append({"tool": "web_path_risk_triage", "result": r2a})

    r2b = ftp_audit(max_items=25, max_previews=10, max_bytes_per_file=8000)
    observations.append({"tool": "ftp_audit", "result": r2b})

    if include_fs:
        r2c = fs_risk_triage(
            root=FS_TRIAGE_ROOT,
            max_findings=FS_TRIAGE_MAX_FINDINGS,
            max_file_bytes=FS_TRIAGE_MAX_FILE_BYTES,
            ignore_dirs=list(DEFAULT_IGNORE_DIRS),
        )
        observations.append({"tool": "fs_risk_triage", "result": r2c})

    r3 = nmap_scan()  # ports are locked down inside nmap_scan
    observations.append({"tool": "nmap_scan", "result": r3})

    return observations



# ============================================================
# LLM plumbing
# ============================================================

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
- Prefer robots_txt_analyser first, then content_type_check(paths=[...]) for validation.
- Use web_path_risk_triage for prioritisation (attacker-visible paths only).
- Use nmap_scan only for confirming expected port exposure at the end.
- If you want to use a tool, output JSON ONLY in this exact format:
  {"tool":"<name>","args":{...}}

If no tool is needed, answer normally in plain English.
Keep outputs short and manager-friendly.
""".strip()

TOOL_CONTROLLER_PROMPT = """TOOL_CALL_ONLY MODE.
Return ONLY a single JSON object for the next tool call.
No prose. No markdown. No code fences. No backticks.
JSON format:
{"tool":"<name>","args":{...}}

Allowed tools:
- robots_txt_analyser (args: {})
- http_get (args: {"path":"/"} )  # choose from known/discovered paths only
- content_type_check (args: {"paths":["/","/robots.txt","/ftp","/admin"]})
- web_path_risk_triage (args: {"content_type_result":{...},"robots_disallow":[...]} )
- ftp_audit (args: {"max_items":25,"max_previews":10,"max_bytes_per_file":8000})
- nmap_scan (args: {"ports":"3000,4000,4001,4002"})  # only at the very end
- fs_risk_triage (args: {"root":".","max_findings":50,"max_file_bytes":26214400,"ignore_dirs":[".git","node_modules"]})
- capabilities_and_rules (args: {})

If you are unsure, choose robots_txt_analyser first.
""".strip()


def call_ollama(messages: List[Dict[str, str]], force_json: bool = False) -> str:
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


def looks_like_tool_intent(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    tl = t.lower()

    if t.startswith("{") and ("tool" in tl or "args" in tl):
        return True
    if '"tool"' in tl or "'tool'" in tl or '"args"' in tl or "'args'" in tl:
        return True

    if any(
        name in tl
        for name in [
            "http_get",
            "robots_txt_analyser",
            "content_type_check",
            "web_path_risk_triage",
            "nmap_scan",
            "ftp_audit",
            "fs_risk_triage",
        ]
    ):
        return True

    return False


def is_tools_question(text: str) -> bool:
    t = (text or "").lower().strip()
    tools_keywords = ["tool", "tools", "capabilit", "guardrail", "allowed", "not allowed", "can't", "cannot", "rules"]
    if not any(k in t for k in tools_keywords):
        return False

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


def capabilities_and_rules() -> dict:
    tools = list_tools()["tools"]
    rows = []
    for t in tools:
        rows.append(
            {
                "tool": t["name"],
                "purpose": t["description"],
                "safety_model": t.get("safety", ""),
                "inputs": {},
            }
        )

    return {
        "tool": "capabilities_and_rules",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "table": {"columns": ["tool", "purpose", "inputs", "safety_model"], "rows": rows},
        "explicitly_not_allowed": not_allowed_rules()["explicitly_not_allowed"],
        "guardrails_enforced_by_code": guardrails_enforced()["guardrails_enforced_by_code"],
    }


def build_tools() -> dict:
    return {
        "http_get": http_get,
        "robots_txt_analyser": robots_txt_analyser,
        "content_type_check": content_type_check,
        "web_path_risk_triage": web_path_risk_triage,
        "nmap_scan": nmap_scan,
        "summary_generator": summary_generator,
        "fs_risk_triage": fs_risk_triage,
        "ftp_audit": ftp_audit,
        "list_tools_table": list_tools_table,
        "not_allowed_rules": not_allowed_rules,
        "guardrails_enforced": guardrails_enforced,
        "describe_target": describe_target,
        "list_tools": list_tools,
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

    # ✅ Deterministic recon shortcut (single entry point)
    lu = (last_user or "").lower()
    if any(k in lu for k in ["recon", "reconnaissance", "juice-shop", "juice shop"]):
        # Enable OPTIONAL host-side FS triage only if the user explicitly asks
        fs_triggers = [
            "file risk",
            "directory risk",
            "file and directory risk",
            "fs triage",
            "filesystem triage",
            "repo triage",
            "local triage",
            "scan my repo",
        ]
        include_fs = any(t in lu for t in fs_triggers)

        print("[RECON] deterministic shortcut HIT:", repr(last_user), "include_fs=", include_fs, flush=True)
        final_text = summary_generator(collect_recon_observations(include_fs=include_fs))["summary"]
        return JSONResponse(
            {
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
        )

    # ✅ ASCII image response
    if is_picture_request(last_user):
        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": SNOOPY_ASCII_ART},
                        "finish_reason": "stop",
                    }
                ],
                "model": MODEL,
            }
        )

    if is_name_question(last_user):
        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": SNOOPY_NAME_RESPONSE},
                        "finish_reason": "stop",
                    }
                ],
                "model": MODEL,
            }
        )

    # ✅ DETERMINISTIC METADATA QUESTIONS (NO RECON)
    if is_guardrails_question(last_user):
        tl = (last_user or "").lower()
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

        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": answer},
                        "finish_reason": "stop",
                    }
                ],
                "model": MODEL,
            }
        )

    if is_list_tools_question(last_user):
        t = list_tools_table()
        md = ["tool | purpose", "--- | ---"]
        for r in t["table"]["rows"]:
            md.append(f"{r['tool']} | {r['purpose']}")
        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "\n".join(md)}, "finish_reason": "stop"}
                ],
                "model": MODEL,
            }
        )

    if is_tools_question(last_user):
        t = capabilities_and_rules()
        lines = ["tool | purpose", "--- | ---"]
        for r in t["table"]["rows"]:
            lines.append(f"{r['tool']} | {r['purpose']}")
        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "\n".join(lines)}, "finish_reason": "stop"}],
                "model": MODEL,
            }
        )

    # ✅ GENERAL CHAT / NON-RECON QUESTIONS
    if is_general_question(last_user):
        convo = [{"role": "system", "content": "Answer the user's question directly and clearly. Do not use tools."}] + user_messages
        answer = call_ollama(convo)
        return JSONResponse(
            {
                "id": "chatcmpl-agentic-demo",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
                "model": MODEL,
            }
        )

    # ---- ONLY NOW do we enter the agent loop ----
    convo = [{"role": "system", "content": SYSTEM_PROMPT}] + user_messages
    observations: List[Dict[str, Any]] = []
    final_text: Optional[str] = None

    discovered_paths: Set[str] = set()

    MAX_STEPS = int(os.getenv("MAX_STEPS", "6"))
    for step in range(MAX_STEPS):
        llm_out = call_ollama(convo)
        tool_call = parse_tool_call(llm_out)

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

        # Guardrail: stop path guessing
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

        try:
            result = TOOLS[tool](**args) if args else TOOLS[tool]()
        except Exception as e:
            final_text = f"Tool '{tool}' failed: {e}"
            break

        if tool == "robots_txt_analyser":
            for p in result.get("disallow_paths", []) or []:
                discovered_paths.add(normalise_path(p))

        observations.append({"tool": tool, "result": result})

        convo.append({"role": "assistant", "content": llm_out})
        tool_text = json.dumps(result, indent=2)
        if len(tool_text) > MAX_TOOL_RESULT_CHARS:
            tool_text = tool_text[:MAX_TOOL_RESULT_CHARS] + "\n...<truncated>..."
        convo.append({"role": "user", "content": f"Tool result (truncated):\n{tool_text}"})

    if final_text is None:
        final_text = "No response generated."

    return JSONResponse(
        {
            "id": "chatcmpl-agentic-demo",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}],
            "model": MODEL,
        }
    )


@app.get("/health")
def health():
    return {"ok": True}
