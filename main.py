"""
Bastion WAF All-in-One Multi-Service Orchestrator Launcher.
Manages WAF Reverse Proxy (8080), Management Dashboard API (8000), and Bank Application (5000).
"""

import argparse
from multiprocessing import Process
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uvicorn

# Ensure the waf directory is on python module path
WAF_DIR = Path(__file__).resolve().parent
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))


def free_port(port: int):
    """Ensure port is available by clearing any stale process holding it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                subprocess.run(f"fuser -k {port}/tcp 2>/dev/null", shell=True)
                time.sleep(0.3)
    except Exception:
        pass


def run_dashboard(host: str = "127.0.0.1", port: int = 8000):
    os.chdir(str(WAF_DIR))
    uvicorn.run("api.server:app", host=host, port=port, log_level="warning")


def run_proxy(host: str = "127.0.0.1", port: int = 8080):
    os.chdir(str(WAF_DIR))
    uvicorn.run("bastion.core.proxy:app", host=host, port=port, log_level="warning")


def run_upstream(host: str = "127.0.0.1", port: int = 5000):
    os.chdir(str(WAF_DIR))
    from vulnerable_target.app import app as bank_app
    bank_app.run(host=host, port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Bastion WAF All-in-One Launcher")
    parser.add_argument(
        "--service",
        choices=["all", "dashboard", "proxy", "upstream"],
        default="all",
        help="Service to start (default: all)",
    )
    args = parser.parse_args()

    if args.service == "dashboard":
        free_port(8000)
        run_dashboard()
    elif args.service == "proxy":
        free_port(8080)
        run_proxy()
    elif args.service == "upstream":
        free_port(5000)
        run_upstream()
    else:
        # Clean up stale ports
        free_port(5000)
        free_port(8000)
        free_port(8080)

        print("\n" + "=" * 68)
        print("🛡️   BASTION WAF & APEX BANK ALL-IN-ONE SYSTEM LAUNCHER")
        print("=" * 68)
        print("  📊  WAF Security Dashboard:      http://127.0.0.1:8000")
        print("  🏦  Protected Bank Portal:       http://127.0.0.1:8080  (via WAF Proxy)")
        print("  🔐  Staff & Security Center:     http://127.0.0.1:8080/staff")
        print("  🎯  Direct Bank Target:          http://127.0.0.1:5000  (Unprotected)")
        print("=" * 68)
        print("  👉  Open http://127.0.0.1:8080 to interact with the bank app.")
        print("  👉  Open http://127.0.0.1:8000 to view live threat telemetry.")
        print("  Press CTRL+C to terminate all services.")
        print("=" * 68 + "\n")

        p_upstream = Process(target=run_upstream, name="Upstream-Bank")
        p_dashboard = Process(target=run_dashboard, name="Dashboard-API")
        p_proxy = Process(target=run_proxy, name="WAF-Proxy")

        processes = [p_upstream, p_dashboard, p_proxy]
        for p in processes:
            p.daemon = True
            p.start()

        def signal_handler(sig, frame):
            print("\nShutting down all Bastion WAF services...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            free_port(5000)
            free_port(8000)
            free_port(8080)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(None, None)


if __name__ == "__main__":
    main()
