"""
High-Performance WAF Reverse Proxy with dynamic upstream routing,
live telemetry logging, and defense bypass support.
"""

from contextlib import asynccontextmanager
import logging
from typing import Optional, Tuple
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from .engine import Engine
from .inspector import inspect_request
from database.db import get_enabled_rule_ids, get_sites, init_db, log_event

logger = logging.getLogger(__name__)

DEFAULT_UPSTREAM = "http://127.0.0.1:5000"

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
        for site in sites:
            domain = site["domain"].lower()
            current_host = host.lower()
            if domain in current_host or current_host in domain:
                target = site["upstream"] if site["upstream"].startswith("http") else f"http://{site['upstream']}"
                return target, bool(site.get("defense_mode", True))
    except Exception:
        pass
    return DEFAULT_UPSTREAM, True


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def waf_proxy(request: Request, path: str):
    body = await request.body()
    query_string = request.url.query
    headers = dict(request.headers)
    client_ip = request.client.host if request.client else "127.0.0.1"
    host_header = request.headers.get("host", "127.0.0.1:8080")

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
        return Response(
            content='{"error": "502 Bad Gateway", "message": "Upstream target server is unreachable."}',
            status_code=502,
            media_type="application/json",
        )
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
