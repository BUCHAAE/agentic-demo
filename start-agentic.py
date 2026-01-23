#!/usr/bin/env python3
#
#  Andrew Buchanan - Jan 2026
#  Agentic demo stack launcher
#  - Starts Juice Shop in Docker
#  - Starts 3 "sidecar" services on extra ports (4000-4002) inside the same container network namespace
#  - Starts Ollama server (if not running)
#  - Starts agent_api Uvicorn server
#  - Starts Streamlit UI

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

ROOT_DIR = Path("/home/buchaae/agentic-demo")
UI_DIR = ROOT_DIR / "agent-ui"
VENV_DIR = ROOT_DIR / "agent-env"

# External (what YOU browse)
JUICE_URL = "http://127.0.0.1:3001"

# Internal container target (what the agent should talk to)
JUICE_CONTAINER_NAME = "juice-shop"
JUICE_INTERNAL_PORT = "3000"  # inside container
JUICE_EXTERNAL_PORT = "3001"  # host mapped port

# Sidecar containers (share network namespace with juice-shop)
SIDECARS = [
    {
        "name": "juice-echo-4000",
        "port": "4000",
        "text": "health OK",
    },
    {
        "name": "juice-echo-4001",
        "port": "4001",
        "text": "metrics endpoint",
    },
    {
        "name": "juice-echo-4002",
        "port": "4002",
        "text": "debug interface",
    },
]
SIDECAR_IMAGE = "hashicorp/http-echo:1.0"

API_URL = "http://127.0.0.1:8000"
UI_URL = "http://127.0.0.1:8501"
OLLAMA_URL = "http://127.0.0.1:11434"

PROCS = []


def which(cmd: str) -> bool:
    return subprocess.call(["bash", "-lc", f"command -v {cmd} >/dev/null 2>&1"]) == 0


def http_ok(url: str, timeout: float = 1.5) -> bool:
    """
    Return True if a web server is reachable.
    Treat 4xx as "up" for service checks.
    """
    try:
        req = UrlRequest(url, headers={"User-Agent": "demo-launcher"})
        with urlopen(req, timeout=timeout) as r:
            return 200 <= getattr(r, "status", 200) < 500
    except HTTPError as e:
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


def docker_container_exists(name: str) -> bool:
    return subprocess.call(["bash", "-lc", f"docker inspect {name} >/dev/null 2>&1"]) == 0


def docker_stop_rm(name: str):
    if docker_container_exists(name):
        subprocess.call(["bash", "-lc", f"docker stop {name} >/dev/null 2>&1 || true"])
        subprocess.call(["bash", "-lc", f"docker rm {name} >/dev/null 2>&1 || true"])


def get_container_ip(name: str) -> str:
    try:
        ip = subprocess.check_output(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return ip or ""
    except Exception:
        return ""


def start_sidecars():
    # Pull once (no lag during demo)
    subprocess.call(["docker", "pull", SIDECAR_IMAGE])

    for sc in SIDECARS:
        docker_stop_rm(sc["name"])
        print(f"[INFO] Starting sidecar {sc['name']} on :{sc['port']} (inside juice-shop netns)")
        subprocess.check_call(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                sc["name"],
                "--network",
                f"container:{JUICE_CONTAINER_NAME}",
                SIDECAR_IMAGE,
                "-listen",
                f":{sc['port']}",
                "-text",
                sc["text"],
            ]
        )


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

    # Stop sidecars
    for sc in SIDECARS:
        print(f"[STOP] docker container: {sc['name']}")
        docker_stop_rm(sc["name"])

    # Stop main container
    print(f"[STOP] docker container: {JUICE_CONTAINER_NAME}")
    docker_stop_rm(JUICE_CONTAINER_NAME)

    print("[DONE]")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    for tool in ["docker", "ollama", "nmap"]:
        if not which(tool):
            print(f"[ERROR] Missing required command: {tool}")
            sys.exit(1)

    # Pull Juice Shop (avoids demo lag)
    subprocess.call(["docker", "pull", "bkimminich/juice-shop"])

    # Hygiene: stop previous runs
    for sc in SIDECARS:
        docker_stop_rm(sc["name"])
    docker_stop_rm(JUICE_CONTAINER_NAME)

    # 1) Start Juice Shop (ONLY map 3001 -> 3000)
    print(f"[INFO] Starting Juice Shop container '{JUICE_CONTAINER_NAME}'...")
    subprocess.check_call(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            JUICE_CONTAINER_NAME,
            "-p",
            f"{JUICE_EXTERNAL_PORT}:{JUICE_INTERNAL_PORT}",
            "bkimminich/juice-shop",
        ],
        cwd=str(ROOT_DIR),
    )

    wait_for(JUICE_URL, "Juice Shop (external)", seconds=45)

    # Resolve container IP (for internal agent targeting)
    juice_ip = ""
    for _ in range(30):
        juice_ip = get_container_ip(JUICE_CONTAINER_NAME)
        if juice_ip:
            break
        time.sleep(0.5)

    if not juice_ip:
        print("[WARN] Could not determine container IP; falling back to localhost mapping (less ideal).")
        juice_base = JUICE_URL
        juice_target = "127.0.0.1"
        juice_target_port = JUICE_EXTERNAL_PORT
    else:
        juice_base = f"http://{juice_ip}:{JUICE_INTERNAL_PORT}"
        juice_target = juice_ip
        juice_target_port = JUICE_INTERNAL_PORT
        print(f"[OK] Juice Shop container IP: {juice_ip}")
        print(f"[OK] Agent JUICE_BASE (internal): {juice_base}")

    # 1b) Start sidecars (creates extra open ports on the SAME container IP)
    start_sidecars()

    # 2) Start Ollama server (if it isn't already)
    if not http_ok(OLLAMA_URL):
        start_process("ollama-serve", ["ollama", "serve"], cwd=str(ROOT_DIR))
        wait_for(OLLAMA_URL, "Ollama", seconds=20)
    else:
        print(f"[OK] Ollama already up: {OLLAMA_URL}")

    # Shared env for agent services
    base_env = os.environ.copy()
    base_env["JUICE_BASE"] = juice_base
    base_env["JUICE_TARGET"] = juice_target
    base_env["JUICE_TARGET_PORT"] = str(juice_target_port)
    # Let nmap_scan default to scanning these ports (agent_api can read it)
    base_env["JUICE_SCAN_PORTS"] = "3000,4000,4001,4002"

    # 3) Start Uvicorn API
    uvicorn_bin = VENV_DIR / "bin" / "uvicorn"
    if not uvicorn_bin.exists():
        print(f"[ERROR] uvicorn not found in venv: {uvicorn_bin}")
        print("Install it in agent-env with: pip install uvicorn")
        sys.exit(1)

    start_process(
        "uvicorn-api",
        [str(uvicorn_bin), "agent_api:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=str(ROOT_DIR),
        env=base_env,
    )
    wait_for(API_URL, "Agent API", seconds=30)

    # 4) Start Streamlit UI
    py = venv_python()
    start_process(
        "streamlit-ui",
        [str(py), "-m", "streamlit", "run", "app.py"],
        cwd=str(UI_DIR),
        env=base_env,
    )
    wait_for(UI_URL, "Streamlit UI", seconds=30)

    print("\n[READY] Demo stack started.")
    print(f"  Juice Shop (browser) : {JUICE_URL}")
    print(f"  Juice Shop (agent)   : {juice_base}")
    print(f"  Ollama               : {OLLAMA_URL}")
    print(f"  API                  : {API_URL}")
    print(f"  Streamlit            : {UI_URL}")
    print("  Extra open ports     : 4000, 4001, 4002 (sidecars in same netns)")
    print("\nPress Ctrl+C to stop everything.")

    while True:
        time.sleep(1)
        for label, p in PROCS:
            if p.poll() is not None:
                print(f"[ERROR] {label} exited with code {p.returncode}. Stopping stack.")
                cleanup()


if __name__ == "__main__":
    main()
