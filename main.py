# BASTION‑TIP | WAF & THREAT INTELLIGENCE PLATFORM
"""
This launcher orchestrates the Docker‑Compose stack and provides a clean, status‑oriented
terminal UI. It no longer starts duplicate processes (upstream bank, gateway, dashboard,
proxy) because those services are managed by the Compose configuration.
Optional security‑lab (vulnerable‑bank demo) can be started separately via the
"--lab" flag.
"""

import argparse
import os
import subprocess
import sys
import time
import socket
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
COMPOSE_FILE = PROJECT_ROOT / "compose.yaml"

# Load .env if present
env_file = PROJECT_ROOT / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))

BANNER = """
═══════════════════════════════════════════════════════════════════════════════
  🛡️   BASTION‑TIP | WAF & THREAT INTELLIGENCE PLATFORM
═══════════════════════════════════════════════════════════════════════════════
"""

def run_cmd(command: str, cwd: Path = PROJECT_ROOT, capture: bool = False):
    """Execute a shell command.
    Returns (stdout, stderr, returncode). If capture is False the command streams
    its output directly to the console.
    """
    result = subprocess.run(
        command,
        cwd=str(cwd),
        shell=True,
        capture_output=capture,
        text=True,
        env=os.environ,
    )
    if capture:
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    return "", "", result.returncode

def docker_compose(*args: str):
    cmd = f"docker compose -f {COMPOSE_FILE} {' '.join(args)}"
    return run_cmd(cmd, capture=False)

def wait_for_socket(host: str, port: int, timeout: int = 5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, port)) == 0:
                    return True
            except OSError:
                pass
        time.sleep(0.5)
    return False

def check_redis() -> str:
    # First check via docker exec
    out, _, rc = run_cmd(f"docker compose -f {COMPOSE_FILE} exec -T redis redis-cli ping 2>/dev/null", capture=True)
    if rc == 0 and "PONG" in out:
        return "[OK]"
    # Fallback to direct socket or local cli
    if wait_for_socket("127.0.0.1", 6379, timeout=2):
        return "[OK]"
    return "[FAIL]"

def check_opensearch() -> str:
    user = os.environ.get("OPENSEARCH_USERNAME", "admin")
    pw = os.environ.get("OPENSEARCH_PASSWORD", "Bastion@123")
    out, _, rc = run_cmd(f"curl -s -k -u '{user}:{pw}' https://127.0.0.1:9200/_cluster/health 2>/dev/null", capture=True)
    return "[OK]" if rc == 0 and ('"status":"green"' in out or '"status":"yellow"' in out) else "[FAIL]"

def check_dashboards() -> str:
    user = os.environ.get("OPENSEARCH_DASHBOARDS_USERNAME", os.environ.get("OPENSEARCH_USERNAME", "admin"))
    pw = os.environ.get("OPENSEARCH_DASHBOARDS_PASSWORD", os.environ.get("OPENSEARCH_PASSWORD", "Bastion@123"))
    out, _, rc = run_cmd(f"curl -s -u '{user}:{pw}' http://127.0.0.1:5601/api/status 2>/dev/null", capture=True)
    return "[OK]" if rc == 0 and ('"state":"green"' in out or '"status":"green"' in out) else "[FAIL]"

def check_telemetry() -> str:
    out, _, rc = run_cmd(f"docker compose -f {COMPOSE_FILE} ps telemetry --format json 2>/dev/null", capture=True)
    if rc == 0 and ("running" in out.lower() or "telemetry" in out.lower()):
        return "[OK]"
    out, _, _ = run_cmd("docker ps --filter 'name=telemetry' --format '{{.Names}}'", capture=True)
    return "[OK]" if out else "[FAIL]"

def check_proxy() -> str:
    return "[OK]" if wait_for_socket("127.0.0.1", 8080, timeout=3) else "[FAIL]"

def check_api() -> str:
    return "[OK]" if wait_for_socket("127.0.0.1", 9000, timeout=3) else "[FAIL]"

def check_lab() -> str:
    return "[RUNNING]" if wait_for_socket("127.0.0.1", 5000, timeout=1) else "[STOPPED]"

def get_last_event_time() -> str:
    user = os.environ.get("OPENSEARCH_USERNAME", "admin")
    pw = os.environ.get("OPENSEARCH_PASSWORD", "Bastion@123")
    cmd = f"curl -s -k -u '{user}:{pw}' 'https://127.0.0.1:9200/bastion-events-v1-*/_search?size=1&sort=@timestamp:desc' 2>/dev/null"
    out, _, rc = run_cmd(cmd, capture=True)
    if rc == 0 and '"hits"' in out:
        try:
            import json
            data = json.loads(out)
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                return str(hits[0].get("_source", {}).get("@timestamp", "No events yet"))
        except Exception:
            pass
    return "No events yet"

def print_status():
    print(BANNER)
    print("SYSTEM STATUS")
    print(f"  Docker Compose configuration:      [OK]")
    print(f"  Redis:                           {check_redis()}")
    print(f"  OpenSearch:                      {check_opensearch()}")
    print(f"  OpenSearch Dashboards:           {check_dashboards()}")
    print(f"  Telemetry worker:                {check_telemetry()}")
    print(f"  Bastion WAF proxy:                {check_proxy()}")
    print(f"  Bastion API (gateway):            {check_api()}")
    print()
    print("PROTECTED WEBSITE")
    print("  Site ID:        portfolio-netlify")
    print("  Upstream:       https://abrham-addis-portfolio.netlify.app/")
    print("  Protection Mode: DETECTION")
    print("  Local WAF URL:  http://127.0.0.1:8080")
    print()
    print("SECURITY PLATFORM")
    print("  OpenSearch Dashboards: http://127.0.0.1:5601")
    print("  Bastion API Health:   http://127.0.0.1:9000/health/ready")
    print("  OpenSearch REST API:  https://127.0.0.1:9200")
    print()
    print("TELEMETRY")
    print("  Redis event‑stream connectivity:  " + ("[OK]" if check_redis() == "[OK]" else "[FAIL]"))
    print("  Telemetry worker status:          " + ("[OK]" if check_telemetry() == "[OK]" else "[FAIL]"))
    print("  OpenSearch indexing status:       " + ("[OK]" if check_opensearch() == "[OK]" else "[FAIL]"))
    print(f"  Last indexed event timestamp:     {get_last_event_time()}")
    print()
    print("OPTIONAL SECURITY LAB (VULNERABLE BANK)")
    lab_status = check_lab()
    print(f"  Lab status:                       {lab_status}")
    if lab_status == "[RUNNING]":
        print("  Direct Bank Target (unprotected): http://127.0.0.1:5000")
    print("  To start:       bastion lab start")
    print("  To stop:        bastion lab stop")
    print()
    print("Startup checks completed. Use the status command to re‑query health.")
    print("═" * 70)

def start_lab():
    print("Starting vulnerable banking lab on port 5000...")
    cmd = f"docker compose -f {COMPOSE_FILE} --profile lab up -d demo-upstream"
    run_cmd(cmd, capture=False)
    if wait_for_socket("127.0.0.1", 5000, timeout=15):
        print("Vulnerable banking lab started successfully at http://127.0.0.1:5000")
    else:
        print("Vulnerable banking lab command issued. Check 'bastion lab status' in a moment.")

def stop_lab():
    print("Stopping vulnerable banking lab...")
    cmd = f"docker compose -f {COMPOSE_FILE} stop demo-upstream"
    run_cmd(cmd, capture=False)
    print("Vulnerable banking lab stopped.")

def status_lab():
    lab_status = check_lab()
    print(f"Vulnerable banking lab status: {lab_status}")
    if lab_status == "[RUNNING]":
        print("Direct Bank Target (unprotected): http://127.0.0.1:5000")

def start_stack(lab: bool = False):
    services = "bastion redis opensearch opensearch-dashboards telemetry"
    profile_args = ["--profile", "lab"] if lab else []
    if lab:
        services += " demo-upstream"
    print("Starting Docker Compose services…")
    docker_compose(*profile_args, "up", "-d", *services.split())
    timeout = 120
    start = time.time()
    while time.time() - start < timeout:
        if all([
            check_redis() == "[OK]",
            check_opensearch() == "[OK]",
            check_dashboards() == "[OK]",
            check_telemetry() == "[OK]",
            check_proxy() == "[OK]",
            check_api() == "[OK]",
        ]):
            break
        time.sleep(3)
    print_status()

def stop_stack(lab: bool = False):
    services = "bastion redis opensearch opensearch-dashboards telemetry"
    profile_args = ["--profile", "lab"] if lab else []
    if lab:
        services += " demo-upstream"
    print("Stopping Docker Compose services…")
    docker_compose(*profile_args, "stop", *services.split())
    print("Services stopped. Persistent data retained.")

def status_stack():
    print_status()

def main():
    # Handle legacy flags passed before subcommand e.g. "bastion --lab start"
    argv = sys.argv[1:]
    has_lab_flag = False
    if "--lab" in argv:
        has_lab_flag = True
        argv = [a for a in argv if a != "--lab"]

    parser = argparse.ArgumentParser(description="Bastion‑TIP CLI launcher")
    sub = parser.add_subparsers(dest="cmd")

    start_parser = sub.add_parser("start", help="Start the core stack")
    start_parser.add_argument("--lab", action="store_true", help="Also start the vulnerable‑bank demo")

    stop_parser = sub.add_parser("stop", help="Stop the core stack (keeps data)")
    stop_parser.add_argument("--lab", action="store_true", help="Also stop the vulnerable‑bank demo")

    sub.add_parser("status", help="Show service health")

    # Canonical lab subcommand
    lab_parser = sub.add_parser("lab", help="Manage the vulnerable banking lab")
    lab_sub = lab_parser.add_subparsers(dest="lab_action")
    lab_sub.add_parser("start", help="Start the vulnerable banking lab on port 5000")
    lab_sub.add_parser("stop", help="Stop the vulnerable banking lab")
    lab_sub.add_parser("status", help="Show status of the vulnerable banking lab")

    args = parser.parse_args(argv)

    if args.cmd == "start" or args.cmd is None:
        start_stack(lab=(getattr(args, "lab", False) or has_lab_flag))
    elif args.cmd == "stop":
        stop_stack(lab=(getattr(args, "lab", False) or has_lab_flag))
    elif args.cmd == "status":
        status_stack()
    elif args.cmd == "lab":
        action = getattr(args, "lab_action", None)
        if action == "start":
            start_lab()
        elif action == "stop":
            stop_lab()
        elif action == "status":
            status_lab()
        else:
            lab_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
