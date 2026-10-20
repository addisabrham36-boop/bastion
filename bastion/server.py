"""
Bastion Container Process Runner.
Spawns and manages both:
1. Bastion WAF Reverse Proxy on 0.0.0.0:8080
2. Bastion Gateway & Control API on 0.0.0.0:9000
"""

from multiprocessing import Process
import os
import signal
import sys
import time
import uvicorn


def run_proxy(host: str = "0.0.0.0", port: int = 8080):
    from bastion.core.proxy import app as proxy_app
    uvicorn.run(proxy_app, host=host, port=port, log_level="info")


def run_gateway(host: str = "0.0.0.0", port: int = 9000):
    from bastion.app import create_app
    from bastion.api.routes.control import router as control_router
    app = create_app()
    app.include_router(control_router)
    uvicorn.run(app, host=host, port=port, log_level="info")


def main():
    listen_host = os.environ.get("BASTION_LISTEN_HOST", "0.0.0.0")
    proxy_port = int(os.environ.get("BASTION_PROXY_PORT", "8080"))
    gateway_port = int(os.environ.get("BASTION_LISTEN_PORT", "9000"))

    p_proxy = Process(target=run_proxy, args=(listen_host, proxy_port), name="Bastion-Proxy", daemon=True)
    p_gateway = Process(target=run_gateway, args=(listen_host, gateway_port), name="Bastion-Gateway", daemon=True)

    p_proxy.start()
    p_gateway.start()

    def signal_handler(sig, frame):
        if p_proxy.is_alive():
            p_proxy.terminate()
        if p_gateway.is_alive():
            p_gateway.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            if not p_proxy.is_alive() or not p_gateway.is_alive():
                signal_handler(None, None)
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
