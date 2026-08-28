"""
Bastion Enterprise WAF — Standalone Security Engine & Reverse Proxy.
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
    """Ensure port is available by terminating stale processes holding it."""
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


def run_test_target(host: str = "127.0.0.1", port: int = 5000):
    os.chdir(str(WAF_DIR))
    try:
        from vulnerable_target.app import app as target_app
        target_app.run(host=host, port=port, debug=False)
    except Exception as e:
        print(f"Test target notice: {e}")


def main():
    parser = argparse.ArgumentParser(description="Bastion Standalone Enterprise WAF")
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=8080, help="WAF reverse proxy port (default: 8080)")
    parser.add_argument("--dashboard-port", type=int, default=8000, help="Security dashboard port (default: 8000)")
    parser.add_argument("--upstream", default=None, help="Default upstream website/server URL (e.g. http://127.0.0.1:3000)")
    parser.add_argument("--with-test-target", action="store_true", help="Launch local test target server on port 5000")
    args = parser.parse_args()

    if args.upstream:
        os.environ["BASTION_UPSTREAM"] = args.upstream

    # Free ports
    free_port(args.dashboard_port)
    free_port(args.proxy_port)
    if args.with_test_target:
        free_port(5000)

    print("\n" + "━" * 66)
    print("  🛡️   BASTION ENTERPRISE WEB APPLICATION FIREWALL (WAF)")
    print("━" * 66)
    print(f"  📊  WAF Security Dashboard:  http://{args.host}:{args.dashboard_port}")
    print(f"  ⚡  WAF Reverse Proxy:       http://{args.host}:{args.proxy_port}")
    if args.upstream:
        print(f"  🎯  Configured Upstream:     {args.upstream}")
    else:
        print("  🎯  Upstream Routing:        Configurable via Dashboard 'Protected Domains'")
    if args.with_test_target:
        print("  🧪  Test Target Server:      http://127.0.0.1:5000")
    print("━" * 66)
    print("  💡  How to Protect Your Website / Web Application:")
    print(f"      1. Open Dashboard -> 'Protected Domains' tab")
    print(f"      2. Add your website domain & upstream IP:Port (with owner permission)")
    print(f"      3. Route web traffic through Bastion Proxy (port {args.proxy_port})")
    print("━" * 66)
    print("  Press CTRL+C to terminate WAF services.\n")

    processes = []
    p_dashboard = Process(target=run_dashboard, args=(args.host, args.dashboard_port), name="Bastion-Dashboard")
    p_proxy = Process(target=run_proxy, args=(args.host, args.proxy_port), name="Bastion-Proxy")
    processes.extend([p_dashboard, p_proxy])

    if args.with_test_target:
        p_test = Process(target=run_test_target, args=("127.0.0.1", 5000), name="Test-Target")
        processes.append(p_test)

    for p in processes:
        p.daemon = True
        p.start()

    def signal_handler(sig, frame):
        print("\nStopping Bastion WAF services...")
        for p in processes:
            if p.is_alive():
                p.terminate()
        free_port(args.dashboard_port)
        free_port(args.proxy_port)
        if args.with_test_target:
            free_port(5000)
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
