"""
High-Performance WAF Reverse Proxy with dynamic upstream routing,
live telemetry logging, and defense bypass support.
"""

from contextlib import asynccontextmanager
import logging
import os
from typing import Optional, Tuple
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from .engine import Engine
from .inspector import inspect_request
from database.db import get_enabled_rule_ids, get_sites, init_db, log_event

logger = logging.getLogger(__name__)

DEFAULT_UPSTREAM = os.environ.get("BASTION_UPSTREAM", "")

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.client = httpx.AsyncClient(follow_redirects=False, timeout=10.0)
    yield
    await app.state.client.aclose()


app = FastAPI(title="Bastion WAF Reverse Proxy", lifespan=lifespan)
engine = Engine()


def resolve_upstream_and_mode(host: str) -> Tuple[str, bool]:
    """Resolve upstream target and defense mode for the given host."""
    try:
        sites = get_sites()
        current_host = host.lower().strip()
        host_no_port = current_host.split(":")[0]
        for site in sites:
            domain = (site.get("domain") or "").lower().strip()
            if not domain:
                continue
            domain_no_port = domain.split(":")[0]
            # Match exact host:port or domain name without port
            if domain == current_host or domain_no_port == host_no_port:
                upstream = site.get("upstream", "")
                target = upstream if upstream.startswith("http") else f"http://{upstream}"
                return target, bool(site.get("defense_mode", True))
    except Exception:
        pass
    return DEFAULT_UPSTREAM, True


def _make_502_response(accept_header: str, upstream_url: str, host_header: str = "") -> Response:
    """Return friendly HTML page for browser navigation, or JSON for API clients."""
    target_display = upstream_url if upstream_url else "(No upstream configured)"
    description = (
        f"The Bastion WAF Reverse Proxy is actively protecting Port <strong>8080</strong>, but the backend server (<code>{target_display}</code>) is currently offline or unreachable."
        if upstream_url
        else f"The Bastion WAF Reverse Proxy received a request for <code>{host_header or 'this domain'}</code>, but no upstream backend server has been mapped to it yet."
    )

    if "text/html" in accept_header:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bastion WAF — Upstream Status</title>
    <style>
        body {{
            background: #000000;
            color: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }}
        .card {{
            background: #0a0a0a;
            border: 1px solid #222222;
            border-radius: 8px;
            padding: 35px;
            max-width: 550px;
            width: 90%;
            text-align: center;
            box-shadow: 0 0 30px rgba(0,0,0,0.8);
        }}
        .badge {{
            display: inline-block;
            background: #ffffff;
            color: #000000;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 800;
            margin-bottom: 15px;
        }}
        h1 {{ font-size: 1.4rem; margin: 0 0 10px 0; }}
        p {{ font-size: 0.88rem; color: #888888; line-height: 1.5; margin: 0 0 20px 0; }}
        code {{ background: #141414; padding: 3px 8px; border-radius: 4px; border: 1px solid #333333; color: #ffffff; }}
        .btn {{
            display: inline-block;
            background: #ffffff;
            color: #000000;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 700;
            text-decoration: none;
            font-size: 0.85rem;
        }}
        .btn:hover {{ background: #cccccc; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">BASTION WAF ACTIVE</div>
        <h1>Upstream Target Status</h1>
        <p>{description}</p>
        <p>
            To add your website domain or configure upstream proxy routes, open the Security Dashboard:
        </p>
        <a href="http://127.0.0.1:8000" class="btn">Open WAF Dashboard (Port 8000)</a>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=502)
    return Response(
        content='{"error": "502 Bad Gateway", "message": "Upstream target server is unreachable or unconfigured. Open dashboard at http://127.0.0.1:8000"}',
        status_code=502,
        media_type="application/json",
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def waf_proxy(request: Request, path: str):
    body = await request.body()
    query_string = request.url.query
    headers = dict(request.headers)
    client_ip = request.client.host if request.client else "127.0.0.1"
    host_header = request.headers.get("host", "127.0.0.1:8080")
    accept_header = headers.get("accept", "")

    target_path = "/" + path if not path.startswith("/") else path
    upstream_target, defense_active = resolve_upstream_and_mode(host_header)

    # 1. Inspect request against WAF rules
    inspection = inspect_request(
        method=request.method,
        path=target_path,
        query_string=query_string,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )

    try:
        enabled_rules = get_enabled_rule_ids()
    except Exception:
        enabled_rules = None

    verdict = engine.evaluate(inspection.request, enabled_rule_ids=enabled_rules)

    # Determine snippet of payload for audit log inspection
    payload_sample = ""
    if query_string:
        payload_sample += f"Query: {query_string}\n"
    if body:
        try:
            payload_sample += f"Body: {body.decode('utf-8', errors='replace')[:500]}\n"
        except Exception:
            pass
    if "user-agent" in headers:
        payload_sample += f"User-Agent: {headers['user-agent']}\n"

    # If defense mode is disabled for this site (Bypass Mode), do not block
    is_blocked = verdict.blocked and defense_active

    # Log event to database
    log_event(
        client_ip=client_ip,
        method=request.method,
        path=target_path,
        blocked=is_blocked,
        rule_id=verdict.rule_id if verdict.blocked else "",
        reason=verdict.reason if verdict.blocked else ("Clean Request" if defense_active else "Bypass Mode Allowed"),
        action="403 Blocked" if is_blocked else ("200 Allowed" if defense_active else "Bypassed Allowed"),
        payload_snippet=payload_sample[:500],
    )

    # Intercept attack vector if blocking is active
    if is_blocked:
        return Response(
            content=f'{{"blocked": true, "rule": "{verdict.rule_id}", "reason": "{verdict.reason}", "status": 403}}',
            status_code=403,
            media_type="application/json",
        )

    # Prepare forwarding headers
    forward_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    forward_headers["x-forwarded-for"] = client_ip
    forward_headers["x-forwarded-proto"] = request.url.scheme
    forward_headers["x-forwarded-host"] = host_header

    # Check if upstream target is configured
    if not upstream_target:
        return _make_502_response(accept_header, "", host_header)

    # Build upstream target URL
    upstream_url = f"{upstream_target.rstrip('/')}/{path.lstrip('/')}" if path else f"{upstream_target.rstrip('/')}/"
    if query_string:
        upstream_url += f"?{query_string}"

    client = getattr(app.state, "client", None)
    own_client = False
    if client is None:
        client = httpx.AsyncClient(follow_redirects=False, timeout=10.0)
        own_client = True

    try:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=forward_headers,
            timeout=10.0,
        )
    except httpx.ConnectError:
        return _make_502_response(accept_header, upstream_url, host_header)
    except httpx.TimeoutException:
        return Response(
            content='{"error": "504 Gateway Timeout", "message": "Upstream target server timed out."}',
            status_code=504,
            media_type="application/json",
        )
    except httpx.RequestError as exc:
        return Response(
            content=f'{{"error": "502 Bad Gateway", "message": "Upstream error: {str(exc)}"}}',
            status_code=502,
            media_type="application/json",
        )
    finally:
        if own_client:
            await client.aclose()

    # Process and rewrite upstream headers
    response_headers = dict(upstream_response.headers)
    for h in HOP_BY_HOP_HEADERS:
        response_headers.pop(h, None)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )
