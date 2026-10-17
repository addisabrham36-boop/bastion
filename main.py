"""
Bastion Enterprise WAF & Threat Intelligence Platform — Master Launcher.
Coordinates:
  1. Vulnerable Bank Target (Port 5000)
  2. Bastion WAF Reverse Proxy (Port 8080)
  3. WAF SOC Dashboard & Telemetry API (Port 8000)
  4. Bastion-TIP Enterprise Gateway (Port 9000)
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

WAF_DIR = Path(__file__).resolve().parent
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))

# Path to the vulnerable target bank application
VULN_APP_PATH = Path("/home/abrham/Projects/vulnerable-target/app.py")
if not VULN_APP_PATH.exists():
    VULN_APP_PATH = WAF_DIR / "vulnerable_target" / "app.py"


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
    if str(WAF_DIR) not in sys.path:
        sys.path.insert(0, str(WAF_DIR))
    from api.server import app as dashboard_app
    uvicorn.run(dashboard_app, host=host, port=port, log_level="warning")


def run_proxy(host: str = "127.0.0.1", port: int = 8080):
    os.chdir(str(WAF_DIR))
    if str(WAF_DIR) not in sys.path:
        sys.path.insert(0, str(WAF_DIR))
    from bastion.core.proxy import app as proxy_app
    uvicorn.run(proxy_app, host=host, port=port, log_level="warning")


def run_gateway(host: str = "127.0.0.1", port: int = 9000):
    os.chdir(str(WAF_DIR))
    if str(WAF_DIR) not in sys.path:
        sys.path.insert(0, str(WAF_DIR))
    from bastion.app import create_app
    from bastion.api.routes.control import router as control_router
    app = create_app()
    app.include_router(control_router)
    uvicorn.run(app, host=host, port=port, log_level="warning")


def run_upstream(host: str = "127.0.0.1", port: int = 5000):
    if VULN_APP_PATH.exists():
        if str(VULN_APP_PATH.parent) not in sys.path:
            sys.path.insert(0, str(VULN_APP_PATH.parent))
        sys.argv = ["app.py"]
        import importlib.util
        spec = importlib.util.spec_from_file_location("vulnerable_bank_app", str(VULN_APP_PATH))
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "app"):
                module.app.run(host=host, port=port, debug=False)
                return
    uvicorn.run("test_app:app", host=host, port=port, log_level="warning")


def main():
    parser = argparse.ArgumentParser(description="Bastion Enterprise WAF & Master Launcher")
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=8080, help="WAF reverse proxy port (default: 8080)")
    parser.add_argument("--dashboard-port", type=int, default=8000, help="Security dashboard port (default: 8000)")
    parser.add_argument("--gateway-port", type=int, default=9000, help="Bastion-TIP Gateway port (default: 9000)")
    parser.add_argument("--upstream-port", type=int, default=5000, help="Vulnerable bank target port (default: 5000)")
    parser.add_argument("--no-upstream", action="store_true", help="Do not start the built-in vulnerable target app")
    args = parser.parse_args()

    # Free ports before binding
    free_port(args.dashboard_port)
    free_port(args.proxy_port)
    free_port(args.gateway_port)
    if not args.no_upstream:
        free_port(args.upstream_port)

    print("\n" + "═" * 70)
    print("  🛡️   BASTION ENTERPRISE WAF & THREAT INTELLIGENCE PLATFORM")
    print("═" * 70)
    print(f"  📊  WAF SOC Dashboard:       http://{args.host}:{args.dashboard_port}")
    print(f"  ⚡  Protected Bank Portal:   http://{args.host}:{args.proxy_port}  (via WAF Proxy)")
    print(f"  🔐  Staff & Security Center: http://{args.host}:{args.proxy_port}/staff")
    print(f"  🚀  Bastion-TIP Gateway:     http://{args.host}:{args.gateway_port}")
    print(f"      - Health Live:           http://{args.host}:{args.gateway_port}/health/live")
    print(f"      - Health Ready:          http://{args.host}:{args.gateway_port}/health/ready")
    print(f"      - Control API:           http://{args.host}:{args.gateway_port}/api/v1/status")
    if not args.no_upstream:
        print(f"  🎯  Direct Bank Target:      http://{args.host}:{args.upstream_port}  (Unprotected)")
    print("═" * 70)
    print("  💡 ALL-IN-ONE DEMO WORKFLOW:")
    print(f"  1. Dashboard:  http://{args.host}:{args.dashboard_port} (live attack telemetry)")
    print(f"  2. Bank WAF:   http://{args.host}:{args.proxy_port} (test attacks: SQLi, XSS, RCE, LFI, SSRF)")
    print(f"  3. Gateway:    http://{args.host}:{args.gateway_port} (Bastion-TIP core data & control plane)")
    print("  Press CTRL+C to terminate all services simultaneously.")
    print("═" * 70 + "\n")

    processes = []
    if not args.no_upstream:
        p_upstream = Process(target=run_upstream, args=(args.host, args.upstream_port), name="Bastion-Upstream")
        processes.append(p_upstream)

    p_dashboard = Process(target=run_dashboard, args=(args.host, args.dashboard_port), name="Bastion-Dashboard")
    p_proxy = Process(target=run_proxy, args=(args.host, args.proxy_port), name="Bastion-Proxy")
    p_gateway = Process(target=run_gateway, args=(args.host, args.gateway_port), name="Bastion-Gateway")
    processes.extend([p_dashboard, p_proxy, p_gateway])

    for p in processes:
        p.daemon = True
        p.start()

    def signal_handler(sig, frame):
        print("\nShutting down Bastion services...")
        for p in processes:
            if p.is_alive():
                p.terminate()
        free_port(args.dashboard_port)
        free_port(args.proxy_port)
        free_port(args.gateway_port)
        if not args.no_upstream:
            free_port(args.upstream_port)
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
