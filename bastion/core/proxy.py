"""
High-Performance WAF Reverse Proxy with dynamic upstream routing,
live telemetry logging, and defense bypass support.
"""

from contextlib import asynccontextmanager
import asyncio
import gzip
import logging
import os
import time
from typing import Optional, Tuple
import zlib
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from pathlib import Path
import uuid
import redis.asyncio as aioredis
from .engine import Engine
from .inspector import inspect_request
from .context import RequestContext, EvaluationState, Detection
from .decision import DecisionEngine, WAFDecision
from .enums import DecisionAction, Mode
from ..rules.registry import RuleRegistry, RuleEngine
from ..rules.exclusions import ExclusionManager
from ..proxy.router import SiteConfig, SiteRepository, ScoreThresholds
from ..proxy.headers import resolve_client_ip
from ..settings import get_settings
from ..storage.ioc_repository import RedisIOCRepository
from ..storage.rate_limiter import RedisRateLimiter, RateLimitResult
from ..threat_intel.service import (
    ThreatIntelService,
    RULE_ID_IP,
    RULE_ID_DOMAIN,
    RULE_ID_PATH,
)
from database.db import get_enabled_rule_ids, get_sites, init_db, log_event
from bastion.storage.event_stream import RedisStreamPublisher
from bastion.telemetry.schemas import (
    SecurityEvent,
    SiteTelemetry,
    ClientTelemetry,
    HttpTelemetry,
    DecisionTelemetry,
    DetectionTelemetry,
    TimingTelemetry,
)

logger = logging.getLogger(__name__)

DEFAULT_UPSTREAM = os.environ.get("BASTION_UPSTREAM", "https://abrham-addis-portfolio.netlify.app")

HOP_BY_HOP_HEADERS = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

# Site configuration repository loaded from sites.yaml
_sites_yaml_path = Path(__file__).resolve().parent.parent / "config" / "sites.yaml"
site_repo = SiteRepository.load_from_yaml(_sites_yaml_path)

# Unified rule registry containing all 148 rules (blocklist + native + adapted legacy CRS rules)
rule_registry = RuleRegistry.create_default()
exclusion_manager = ExclusionManager()
rule_engine = RuleEngine(rule_registry, exclusion_manager)
decision_engine = DecisionEngine()
legacy_engine = Engine()

# Threat Intelligence Service & IOC Repository
ioc_repo = RedisIOCRepository(None)
threat_intel_service = ThreatIntelService(ioc_repo, exclusion_manager)

# Redis Rate Limiter (bound to Redis in lifespan, fail-open if unavailable)
rate_limiter = RedisRateLimiter(None)

# Retain legacy engine symbol for backward compatibility
engine = legacy_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.client = httpx.AsyncClient(follow_redirects=False, timeout=10.0)
    app.state.site_repo = site_repo
    app.state.rule_registry = rule_registry
    app.state.exclusion_manager = exclusion_manager
    app.state.rule_engine = rule_engine
    app.state.decision_engine = decision_engine
    app.state.legacy_engine = legacy_engine
    app.state.ioc_repo = ioc_repo
    app.state.threat_intel_service = threat_intel_service
    app.state.rate_limiter = rate_limiter
    try:
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0" if os.path.exists("/.dockerenv") else "redis://127.0.0.1:6379/0")
        redis_client = aioredis.from_url(redis_url)
        ioc_repo.redis = redis_client
        rate_limiter.redis = redis_client
        app.state.event_publisher = RedisStreamPublisher(redis_client)
    except Exception as e:
        logger.warning("Could not initialize Redis publisher/IOC repo: %s", e)
        app.state.event_publisher = None
    yield
    await app.state.client.aclose()
    if getattr(app.state, "event_publisher", None) and app.state.event_publisher.redis:
        try:
            await app.state.event_publisher.redis.aclose()
        except Exception:
            pass


app = FastAPI(title="Bastion WAF Reverse Proxy", lifespan=lifespan)
app.state.client = None  # Set to real httpx.AsyncClient by lifespan; None here enables monkeypatch in tests
app.state.site_repo = site_repo
app.state.rule_registry = rule_registry
app.state.exclusion_manager = exclusion_manager
app.state.rule_engine = rule_engine
app.state.decision_engine = decision_engine
app.state.legacy_engine = legacy_engine
app.state.ioc_repo = ioc_repo
app.state.threat_intel_service = threat_intel_service
app.state.rate_limiter = rate_limiter


def resolve_upstream_and_mode(host: str) -> Tuple[str, bool]:
    """Resolve upstream target and defense mode for the given host."""
    try:
        sites = get_sites()
        current_host = host.lower().strip()
        host_no_port = current_host.split(":")[0]

        # Pass 1: Exact host:port match
        for site in sites:
            domain = (site.get("domain") or "").lower().strip()
            if domain == current_host:
                upstream = site.get("upstream", "")
                target = upstream if upstream.startswith("http") else f"http://{upstream}"
                return target, bool(site.get("defense_mode", True))

        # Pass 2: Exact domain name match without port
        for site in sites:
            domain = (site.get("domain") or "").lower().strip()
            if not domain:
                continue
            domain_no_port = domain.split(":")[0]
            if domain_no_port == host_no_port:
                upstream = site.get("upstream", "")
                target = upstream if upstream.startswith("http") else f"http://{upstream}"
                return target, bool(site.get("defense_mode", True))

        # Pass 3: Loopback and local testing aliases
        if host_no_port in ("127.0.0.1", "localhost", "testserver", "testclient"):
            for site in sites:
                domain = (site.get("domain") or "").lower().strip()
                domain_no_port = domain.split(":")[0]
                if domain_no_port in ("127.0.0.1", "localhost", "testserver", "testclient"):
                    upstream = site.get("upstream", "")
                    target = upstream if upstream.startswith("http") else f"http://{upstream}"
                    return target, bool(site.get("defense_mode", True))
            return DEFAULT_UPSTREAM, False
    except Exception:
        pass
    # Unknown hostnames and arbitrary client-selected upstreams remain rejected
    return "", False


def _make_403_response(accept_header: str, rule_id: str, reason: str, client_ip: str, path: str) -> Response:
    """Return high-impact WAF intercept HTML page for browsers, or JSON for API clients."""
    if "text/html" in accept_header:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden — Bastion WAF Attack Intercept</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
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
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: #0a0a0a;
            border: 1px solid #ef4444;
            border-radius: 12px;
            padding: 40px;
            max-width: 600px;
            width: 100%;
            text-align: center;
            box-shadow: 0 0 50px rgba(239, 68, 68, 0.25);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #ef4444;
            color: #ffffff;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.82rem;
            font-weight: 800;
            margin-bottom: 20px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        h1 {{ font-size: 1.6rem; margin: 0 0 12px 0; color: #ffffff; }}
        p.subtitle {{ font-size: 0.95rem; color: #a1a1aa; line-height: 1.5; margin: 0 0 25px 0; }}
        .details-box {{
            background: #121212;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: 16px 20px;
            text-align: left;
            margin-bottom: 25px;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .detail-row {{ display: flex; justify-content: space-between; border-bottom: 1px solid #1f1f23; padding-bottom: 6px; }}
        .detail-row:last-child {{ border-bottom: none; padding-bottom: 0; }}
        .detail-label {{ color: #71717a; font-weight: 600; }}
        .detail-value {{ color: #ffffff; font-family: monospace; font-weight: 700; }}
        .btn-group {{ display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #ffffff;
            color: #000000;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 700;
            text-decoration: none;
            font-size: 0.85rem;
            transition: background 0.15s;
        }}
        .btn:hover {{ background: #d4d4d4; }}
        .btn-secondary {{
            background: transparent;
            color: #ffffff;
            border: 1px solid #3f3f46;
        }}
        .btn-secondary:hover {{ background: #18181b; border-color: #71717a; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge"><i class="fa-solid fa-shield-halved"></i> Attack Intercepted (403 Forbidden)</div>
        <h1>Request Blocked by Bastion WAF</h1>
        <p class="subtitle">
            The Bastion Web Application Firewall inspected your incoming HTTP request and detected a malicious attack signature. The request was blocked inline and prevented from reaching the backend banking system.
        </p>
        <div class="details-box">
            <div class="detail-row">
                <span class="detail-label">Triggered Rule ID:</span>
                <span class="detail-value" style="color: #f87171;">{rule_id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Detection Reason:</span>
                <span class="detail-value">{reason}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Client IP Address:</span>
                <span class="detail-value">{client_ip}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Target URI:</span>
                <span class="detail-value">{path}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">WAF Action:</span>
                <span class="detail-value" style="color: #ef4444;">403 FORBIDDEN INTERCEPT</span>
            </div>
        </div>
        <div class="btn-group">
            <a href="http://127.0.0.1:8080" class="btn"><i class="fa-solid fa-arrow-left"></i> Return to Bank Portal</a>
            <a href="http://127.0.0.1:8000" target="_blank" class="btn btn-secondary"><i class="fa-solid fa-chart-line"></i> Open SOC Dashboard (Port 8000)</a>
        </div>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=403)

    return Response(
        content=f'{{"blocked": true, "rule": "{rule_id}", "reason": "{reason}", "status": 403}}',
        status_code=403,
        media_type="application/json",
    )


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


def _make_429_response(accept_header: str, retry_after: int, client_ip: str, path: str) -> Response:
    """Return high-impact rate limit HTML page for browsers or JSON for API clients."""
    headers = {"Retry-After": str(retry_after)}
    if "text/html" in accept_header:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>429 Too Many Requests — Bastion WAF Rate Limit</title>
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
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: #0a0a0a;
            border: 1px solid #f59e0b;
            border-radius: 12px;
            padding: 40px;
            max-width: 600px;
            width: 100%;
            text-align: center;
            box-shadow: 0 0 50px rgba(245, 158, 11, 0.25);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #f59e0b;
            color: #000000;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.82rem;
            font-weight: 800;
            margin-bottom: 20px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        h1 {{ font-size: 1.6rem; margin: 0 0 12px 0; color: #ffffff; }}
        p.subtitle {{ font-size: 0.95rem; color: #a1a1aa; line-height: 1.5; margin: 0 0 25px 0; }}
        .details-box {{
            background: #121212;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: 16px 20px;
            text-align: left;
            margin-bottom: 25px;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .detail-row {{ display: flex; justify-content: space-between; border-bottom: 1px solid #1f1f23; padding-bottom: 6px; }}
        .detail-row:last-child {{ border-bottom: none; padding-bottom: 0; }}
        .detail-label {{ color: #71717a; font-weight: 600; }}
        .detail-value {{ color: #ffffff; font-family: monospace; font-weight: 700; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">Rate Limit Exceeded (429)</div>
        <h1>Too Many Requests</h1>
        <p class="subtitle">
            The Bastion Web Application Firewall rate limiter has throttled your requests to protect upstream infrastructure.
        </p>
        <div class="details-box">
            <div class="detail-row">
                <span class="detail-label">Client IP:</span>
                <span class="detail-value">{client_ip}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Target URI:</span>
                <span class="detail-value">{path}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Retry After:</span>
                <span class="detail-value" style="color: #f59e0b;">{retry_after} seconds</span>
            </div>
        </div>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=429, headers=headers)

    return Response(
        content=f'{{"blocked": true, "error": "Too Many Requests", "retry_after": {retry_after}, "status": 429}}',
        status_code=429,
        headers=headers,
        media_type="application/json",
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def waf_proxy(request: Request, path: str):
    start_time = time.perf_counter()
    body = await request.body()
    query_string = request.url.query
    headers = dict(request.headers)
    peer_ip = request.client.host if request.client else "127.0.0.1"
    trusted_cidrs = get_settings().trusted_proxies_list
    client_ip, ip_source = resolve_client_ip(peer_ip, headers, trusted_cidrs)
    host_header = request.headers.get("host", "127.0.0.1:8080")
    accept_header = headers.get("accept", "")

    target_path = "/" + path if not path.startswith("/") else path
    upstream_target, defense_active = resolve_upstream_and_mode(host_header)

    # 1. Normalize and inspect request (preserves raw_body and normalized text)
    inspection = inspect_request(
        method=request.method,
        path=target_path,
        query_string=query_string,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )

    # 2. Resolve SiteConfig and mode
    site_cfg = site_repo.resolve_site(host_header)
    mode_str = "prevention" if defense_active else "detection"
    if site_cfg:
        site_config = site_cfg.model_copy(update={"mode": mode_str})
    else:
        site_config = SiteConfig(
            id="portfolio-netlify",
            hostnames=[host_header],
            upstream_origin=upstream_target or DEFAULT_UPSTREAM,
            mode=mode_str,
            score_thresholds=ScoreThresholds(log=20, block=50),
        )

    # 3. Build immutable RequestContext with attached normalized representation
    context = RequestContext.create(
        site_id=site_config.id,
        site_host=host_header,
        client_ip=client_ip,
        client_ip_source=ip_source,
        method=request.method,
        raw_path=target_path,
        raw_query=query_string,
        headers=headers,
        body_bytes=body if isinstance(body, bytes) else body.encode("utf-8", errors="replace"),
        canonical_path=inspection.request.path,
        query_params=inspection.request.query_params,
        form_params={},
        json_body=None,
        text_body=inspection.request.body,
        normalized=inspection.request,
    )

    try:
        enabled_rules = get_enabled_rule_ids()
    except Exception:
        enabled_rules = None

    # --- Redis Rate Limiting Enforcement ---
    rate_limit_enabled = (
        get_settings().bastion_rate_limit_enabled
        and os.environ.get("BASTION_RATE_LIMIT_ENABLED", "true").lower() == "true"
    )
    rl_config = None
    if rate_limit_enabled and site_config.rate_limits:
        # Precedence: exact route rule -> site default rule
        if target_path in site_config.rate_limits:
            cfg = site_config.rate_limits[target_path]
            if getattr(cfg, "enabled", True):
                rl_config = cfg
        elif "default" in site_config.rate_limits:
            cfg = site_config.rate_limits["default"]
            if getattr(cfg, "enabled", True):
                rl_config = cfg

    rl_limiter: RedisRateLimiter = getattr(app.state, "rate_limiter", rate_limiter)
    if rate_limit_enabled and rl_config and rl_limiter:
        dimension = f"route:{target_path}" if target_path in site_config.rate_limits else "ip"
        rl_result: RateLimitResult = await rl_limiter.evaluate_limit(
            site_id=site_config.id,
            dimension=dimension,
            value=client_ip,
            limit=rl_config.requests,
            window_seconds=rl_config.window_seconds,
            request_id=context.request_id,
        )

        if not rl_result.allowed:
            # Over rate limit!
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if site_config.mode == "prevention":
                log_event(
                    client_ip=client_ip,
                    method=request.method,
                    path=target_path,
                    blocked=True,
                    rule_id="RATE_LIMIT_EXCEEDED",
                    reason=f"Rate limit exceeded ({rl_config.requests} req / {rl_config.window_seconds}s)",
                    action="429 Rate Limited",
                    payload_snippet="",
                    duration_ms=duration_ms,
                )
                publisher = getattr(app.state, "event_publisher", None)
                if publisher:
                    try:
                        event_obj = SecurityEvent(
                            request_id=context.request_id,
                            site=SiteTelemetry(id=site_config.id, host=host_header),
                            client=ClientTelemetry(ip=client_ip, ip_source=ip_source, user_agent=headers.get("user-agent")),
                            http=HttpTelemetry(method=request.method, path=target_path, status_code=429),
                            decision=DecisionTelemetry(
                                mode="prevention",
                                would_action="BLOCK",
                                enforced_action="BLOCK",
                                threat_score=100,
                                reason_codes=["RATE_LIMIT_EXCEEDED"],
                            ),
                            detections=[
                                DetectionTelemetry(
                                    rule_id="RATE_LIMIT_EXCEEDED",
                                    category="rate_limiting",
                                    severity="high",
                                    confidence=1.0,
                                    score=100,
                                )
                            ],
                            timing=TimingTelemetry(total_ms=duration_ms, inspection_ms=duration_ms),
                        )
                        await publisher.publish_event(event_obj.model_dump(by_alias=True))
                    except Exception as err:
                        logger.debug("Failed to publish rate limit event to Redis: %s", err)

                return _make_429_response(
                    accept_header=accept_header,
                    retry_after=rl_result.retry_after,
                    client_ip=client_ip,
                    path=target_path,
                )
            else:
                # Detection mode: log observation but allow request through
                log_event(
                    client_ip=client_ip,
                    method=request.method,
                    path=target_path,
                    blocked=False,
                    rule_id="RATE_LIMIT_EXCEEDED",
                    reason=f"Detection Mode Rate Limit Observed ({rl_config.requests} req / {rl_config.window_seconds}s)",
                    action="Detection Mode Rate Limit Observed",
                    payload_snippet="",
                    duration_ms=duration_ms,
                )

    # 4. Scored evaluation with safe fallback to legacy engine
    pipeline_fallback_used = False
    try:
        eval_state: EvaluationState = rule_engine.evaluate(
            context,
            enabled_rule_ids=set(enabled_rules) if enabled_rules is not None else None,
        )

        # Threat Intelligence evaluation (IP, Domain, Path indicators)
        ti_service: ThreatIntelService = getattr(app.state, "threat_intel_service", threat_intel_service)
        if ti_service:
            try:
                ioc_detections = await ti_service.evaluate_request(
                    context,
                    enabled_rule_ids=set(enabled_rules) if enabled_rules is not None else None,
                )
                for det in ioc_detections:
                    eval_state.add_detection(det)
            except Exception as ti_err:
                logger.warning("Threat Intel evaluation failed: %s", ti_err)

        decision: WAFDecision = decision_engine.decide(
            context=context,
            state=eval_state,
            site=site_config,
        )
    except Exception as exc:
        logger.error(
            "Scored decision pipeline raised exception (%s); executing guarded legacy fallback",
            exc,
            exc_info=True,
        )
        pipeline_fallback_used = True
        verdict = legacy_engine.evaluate(inspection.request, enabled_rule_ids=enabled_rules)
        eval_state = EvaluationState()
        if verdict and verdict.blocked:
            eval_state.add_detection(Detection(
                rule_id=verdict.rule_id,
                category="payload",
                severity="high",
                confidence=1.0,
                score=50,
                message=verdict.reason,
                location=verdict.meta.get("field", "request") if isinstance(verdict.meta, dict) else "request",
                evidence=str(verdict.meta.get("matched_value", verdict.reason))[:256] if isinstance(verdict.meta, dict) else str(verdict.reason)[:256],
                proposed_action="BLOCK",
            ))
        decision = decision_engine.decide(context, eval_state, site_config)

    is_blocked = (decision.action == DecisionAction.BLOCK)

    # Primary detection metadata for response and legacy logs
    primary_rule_id = eval_state.detections[0].rule_id if eval_state.detections else ""
    primary_reason = eval_state.detections[0].message if eval_state.detections else (
        "Clean Request" if defense_active else "Bypass Mode Allowed"
    )

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

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Log event to database
    log_event(
        client_ip=client_ip,
        method=request.method,
        path=target_path,
        blocked=is_blocked,
        rule_id=primary_rule_id,
        reason=primary_reason,
        action="403 Blocked" if is_blocked else (
            "200 Allowed" if (decision.would_action == DecisionAction.ALLOW) else "Detection Mode Allowed"
        ),
        payload_snippet=payload_sample[:500],
        duration_ms=duration_ms,
    )

    # Publish SecurityEvent to Redis Stream for Telemetry Worker
    publisher = getattr(app.state, "event_publisher", None)
    if publisher:
        try:
            telemetry_detections = [
                DetectionTelemetry(
                    rule_id=d.rule_id,
                    category=d.category,
                    severity=d.severity,
                    confidence=d.confidence,
                    score=d.score,
                )
                for d in eval_state.detections
            ]
            event_obj = SecurityEvent(
                request_id=context.request_id,
                site=SiteTelemetry(id=site_config.id, host=host_header),
                client=ClientTelemetry(ip=client_ip, ip_source=ip_source, user_agent=headers.get("user-agent")),
                http=HttpTelemetry(method=request.method, path=target_path, status_code=403 if is_blocked else 200),
                decision=DecisionTelemetry(
                    mode=decision.mode.value,
                    would_action=decision.would_action.value,
                    enforced_action=decision.action.value,
                    threat_score=decision.threat_score,
                    reason_codes=decision.reason_codes,
                ),
                detections=telemetry_detections,
                timing=TimingTelemetry(total_ms=duration_ms, inspection_ms=duration_ms),
            )
            await publisher.publish_event(event_obj.model_dump(by_alias=True))
        except Exception as err:
            logger.debug("Failed to publish telemetry event to Redis: %s", err)

    # Intercept attack vector if blocking is active
    if is_blocked:
        return _make_403_response(
            accept_header=accept_header,
            rule_id=primary_rule_id,
            reason=primary_reason,
            client_ip=client_ip,
            path=target_path,
        )

    # Check if upstream target is configured
    if not upstream_target:
        return JSONResponse(
            status_code=421,
            content={
                "error": "Misdirected Request",
                "message": f"Host '{host_header}' is not configured on this Bastion gateway.",
            },
        )

    # Prepare forwarding headers
    forward_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    forward_headers["x-forwarded-for"] = client_ip
    forward_headers["x-forwarded-proto"] = request.url.scheme
    forward_headers["x-forwarded-host"] = host_header
    forward_headers["x-bastion-proxy"] = "1"
    # Request uncompressed representation from upstream to avoid content-encoding mismatches
    forward_headers["accept-encoding"] = "identity"

    # Build upstream target URL
    upstream_url = f"{upstream_target.rstrip('/')}/{path.lstrip('/')}" if path else f"{upstream_target.rstrip('/')}/"
    if query_string:
        upstream_url += f"?{query_string}"

    client = getattr(app.state, "client", None)
    own_client = False
    if client is None:
        client = httpx.AsyncClient(follow_redirects=False, timeout=10.0, verify=True)
        own_client = True

    upstream_response = None
    max_retries = 2
    for attempt in range(1, max_retries + 1):
        try:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                content=body,
                headers=forward_headers,
                timeout=10.0,
            )
            break
        except httpx.ConnectError as exc:
            if attempt < max_retries:
                logger.warning(
                    "Upstream connection failed for %s (%s): %s; retrying attempt %d/%d...",
                    upstream_url,
                    host_header,
                    exc,
                    attempt + 1,
                    max_retries,
                )
                await asyncio.sleep(0.1)
            else:
                logger.error(
                    "Upstream connection permanently failed for %s (%s) after %d attempts: %s",
                    upstream_url,
                    host_header,
                    max_retries,
                    exc,
                )
                return _make_502_response(accept_header, upstream_url, host_header)
        except httpx.TimeoutException as exc:
            logger.warning("Upstream timeout for %s (%s): %s", upstream_url, host_header, exc)
            return Response(
                content='{"error": "504 Gateway Timeout", "message": "Upstream target server timed out."}',
                status_code=504,
                media_type="application/json",
            )
        except httpx.RequestError as exc:
            logger.error("Upstream request error for %s (%s): %s", upstream_url, host_header, exc)
            return Response(
                content=f'{{"error": "502 Bad Gateway", "message": "Upstream error: {str(exc)}"}}',
                status_code=502,
                media_type="application/json",
            )
        finally:
            if own_client:
                await client.aclose()

    if upstream_response is None:
        return _make_502_response(accept_header, upstream_url, host_header)

    # Extract body and decompress if upstream returned compressed bytes that were not decoded
    content = upstream_response.content
    content_encoding = (upstream_response.headers.get("content-encoding") or "").lower().strip()
    if content.startswith(b"\x1f\x8b"):
        try:
            content = gzip.decompress(content)
        except Exception:
            pass
    elif content_encoding in ("br", "brotli"):
        try:
            import brotli
            content = brotli.decompress(content)
        except Exception:
            pass
    elif content_encoding == "deflate" and content.startswith(b"\x78"):
        try:
            content = zlib.decompress(content)
        except Exception:
            pass

    # Process and rewrite upstream headers
    response_headers = dict(upstream_response.headers)
    strip_headers = HOP_BY_HOP_HEADERS | {"content-encoding", "content-length", "transfer-encoding"}
    for h in list(response_headers.keys()):
        if h.lower() in strip_headers:
            response_headers.pop(h, None)

    return Response(
        content=content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )
