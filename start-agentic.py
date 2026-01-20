#!/usr/bin/env python3
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError   # <-- CHANGED: add HTTPError

ROOT_DIR = Path("/home/buchaae/agentic-demo")
UI_DIR = ROOT_DIR / "agent-ui"
VENV_DIR = ROOT_DIR / "agent-env"

JUICE_URL = "http://127.0.0.1:3001"
API_URL = "http://127.0.0.1:8000"
UI_URL = "http://127.0.0.1:8501"
OLLAMA_URL = "http://127.0.0.1:11434"

PROCS = []


def which(cmd: str) -> bool:
    return subprocess.call(["bash", "-lc", f"command -v {cmd} >/dev/null 2>&1"]) == 0


def http_ok(url: str, timeout: float = 1.5) -> bool:
    """
    Return True if a web server is reachable.
    Note: urllib raises HTTPError for 4xx/5xx; for 'is it up?' checks we treat 4xx as up.
    """
    try:
        req = Request(url, headers={"User-Agent": "demo-launcher"})
        with urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 500
    except HTTPError as e:
        # 404 etc. means the server is up, just that the route doesn't exist
        return 200 <= e.code < 500
    except URLError:
        return False
    except Exception:
        return False


def wait_for(url: str, name: str, seconds: int = 30) -> bool:
    start = time.time()
    while time.time() - start < seconds:
        if http_ok(url):
            print(f"[OK] {name} is up: {url}")
            return True
        time.sleep(0.5)
    print(f"[WARN] Timed out waiting for {name}: {url}")
    return False


def start_process(label: str, cmd, cwd=None, env=None):
    cmd = [str(c) for c in cmd]
    print(f"[START] {label}: {' '.join(cmd)}")
    p = subprocess.Popen(cmd, cwd=cwd, env=env)
    PROCS.append((label, p))
    return p


def venv_python() -> Path:
    py = VENV_DIR / "bin" / "python"
    if not py.exists():
        print(f"[ERROR] Venv python not found at: {py}")
        print("Create it with: python3 -m venv ~/agentic-demo/agent-env && pip install -r requirements.txt")
        sys.exit(1)
    return py


def cleanup(*_):
    print("\n[STOP] Shutting down...")

    # Stop non-docker procs first
    for label, p in reversed(PROCS):
        if p.poll() is None:
            print(f"[STOP] {label}")
            try:
                p.terminate()
            except Exception:
                pass

    time.sleep(1.5)

    for label, p in reversed(PROCS):
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass

    print("[DONE]")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Basic tool checks
    for tool in ["docker", "ollama"]:
        if not which(tool):
            print(f"[ERROR] Missing required command: {tool}")
            sys.exit(1)

    # Optional: pre-pull juice-shop image (avoids demo lag)
    subprocess.call(["docker", "pull", "bkimminich/juice-shop"])

    # 0) Demo hygiene: stop any existing juice-shop containers to avoid port 3001 clashes
    subprocess.call(["bash", "-lc", "docker ps -q --filter 'ancestor=bkimminich/juice-shop' | xargs -r docker stop"])

    # 1) Start Juice Shop (docker)
    start_process(
        "juice-shop",
        ["docker", "run", "--rm", "-p", "3001:3000", "bkimminich/juice-shop"],
        cwd=str(ROOT_DIR),
    )
    wait_for(JUICE_URL, "Juice Shop", seconds=45)

    # 2) Start Ollama server (if it isn't already)
    if not http_ok(OLLAMA_URL):
        start_process("ollama-serve", ["ollama", "serve"], cwd=str(ROOT_DIR))
        wait_for(OLLAMA_URL, "Ollama", seconds=20)
    else:
        print(f"[OK] Ollama already up: {OLLAMA_URL}")

    # 3) Start Uvicorn API (agent_api.py is in ROOT_DIR)
    uvicorn_bin = VENV_DIR / "bin" / "uvicorn"
    if not uvicorn_bin.exists():
        print(f"[ERROR] uvicorn not found in venv: {uvicorn_bin}")
        print("Install it in agent-env with: pip install uvicorn")
        sys.exit(1)

    start_process(
        "uvicorn-api",
        [
            str(uvicorn_bin),
            "agent_api:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            # "--reload",  # optional (I'd remove for the demo)
        ],
        cwd=str(ROOT_DIR),  # IMPORTANT: import agent_api from project root
    )
    wait_for(API_URL, "Agent API", seconds=30)

    # 4) Start Streamlit UI (app.py is in agent-ui)
    py = venv_python()
    start_process(
        "streamlit-ui",
        [str(py), "-m", "streamlit", "run", "app.py"],
        cwd=str(UI_DIR),
    )
    wait_for(UI_URL, "Streamlit UI", seconds=30)

    print("\n[READY] Demo stack started.")
    print(f"  Juice Shop : {JUICE_URL}")
    print(f"  Ollama     : {OLLAMA_URL}")
    print(f"  API        : {API_URL}")
    print(f"  Streamlit  : {UI_URL}")
    print("\nPress Ctrl+C to stop everything.")

    # Keep running while processes run
    while True:
        time.sleep(1)
        for label, p in PROCS:
            if p.poll() is not None:
                print(f"[ERROR] {label} exited with code {p.returncode}. Stopping stack.")
                cleanup()


if __name__ == "__main__":
    main()