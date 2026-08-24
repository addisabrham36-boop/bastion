import argparse
from multiprocessing import Process
import os
import signal
import socket
import subprocess
import sys
import time
import uvicorn


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


def run_dashboard(host="127.0.0.1", port=8000):
    uvicorn.run("api.server:app", host=host, port=port, log_level="warning")


def run_proxy(host="127.0.0.1", port=8080):
    uvicorn.run("bastion.core.proxy:app", host=host, port=port, log_level="warning")


def run_upstream(host="127.0.0.1", port=5000):
    vulnerable_target_app = "/home/abrham/vulnerable-target/app.py"
    vulnerable_target_py = "/home/abrham/vulnerable-target/venv/bin/python"
    if os.path.exists(vulnerable_target_app) and os.path.exists(vulnerable_target_py):
        subprocess.run([vulnerable_target_py, vulnerable_target_app])
    else:
        uvicorn.run("test_app:app", host=host, port=port, log_level="warning")


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
        # 1. Clean up stale ports
        free_port(5000)
        free_port(8000)
        free_port(8080)

        print("\n" + "=" * 64)
        print("🛡️   BASTION WAF ALL-IN-ONE SYSTEM LAUNCHER")
        print("=" * 64)
        print("  📊  WAF Security Dashboard:  http://127.0.0.1:8000")
        print("  🏦  Protected Bank Portal:   http://127.0.0.1:8080 (via WAF)")
        print("  🎯  Direct Upstream Target:  http://127.0.0.1:5000 (unprotected)")
        print("=" * 64)
        print("  👉  Open http://127.0.0.1:8080 to interact with the bank app.")
        print("  👉  Open http://127.0.0.1:8000 to view live threat telemetry.")
        print("  Press CTRL+C to stop all services simultaneously.")
        print("=" * 64 + "\n")

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

