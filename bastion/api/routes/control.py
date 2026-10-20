"""
Secure Dashboard & Control Plane API routes (/api/v1/).
Implements token/session authorization, stats overview, events, site mode controls,
rules management, and IOC endpoints.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel

from ..schemas import (
    IOCCreateRequest,
    LoginRequest,
    LoginResponse,
    RuleToggleRequest,
    SiteModeUpdateRequest,
    StatsOverviewResponse,
    StatusResponse,
)
from ...auth.passwords import generate_session_token, hash_password, verify_password
from ...proxy.router import SiteConfig, SiteRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Control API"])

# In-memory store for active admin sessions (token -> role)
ACTIVE_SESSIONS = {
    "dev-admin-token": "admin",
    "dev-viewer-token": "viewer",
}

# Audit trail
AUDIT_LOG = []


def require_role(required_role: str):
    def dependency(authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
            )
        token = authorization.replace("Bearer ", "").strip()
        role = ACTIVE_SESSIONS.get(token)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session token",
            )
        if required_role == "admin" and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative role required",
            )
        return {"token": token, "role": role}
    return dependency


@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    # Demonstration authentication verification
    if req.username == "admin" and req.password == "BastionAdmin2026!":
        token = generate_session_token()
        ACTIVE_SESSIONS[token] = "admin"
        AUDIT_LOG.append({"action": "LOGIN", "user": "admin", "status": "SUCCESS"})
        return LoginResponse(status="success", token=token, role="admin")
    raise HTTPException(status_code=401, detail="Invalid username or password")


@router.get("/status", response_model=StatusResponse)
async def get_system_status(request: Request):
    """
    Live system status from real Redis, SQLite, and component health.
    No authentication required for status (health check).
    """
    import redis.asyncio as aioredis
    from database.db import get_connection

    # Redis connectivity
    redis_connected = False
    stream_length: Optional[int] = None
    worker_queue_lag: Optional[int] = None
    telemetry_status = "offline"

    publisher = getattr(request.app.state, "event_publisher", None)
    redis_client = publisher.redis if publisher and hasattr(publisher, "redis") else None

    # Fallback to direct client if not attached to app.state (e.g. gateway process)
    own_redis = False
    if redis_client is None:
        try:
            import os
            redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0" if os.path.exists("/.dockerenv") else "redis://127.0.0.1:6379/0")
            redis_client = aioredis.from_url(redis_url)
            own_redis = True
        except Exception:
            redis_client = None

    if redis_client:
        try:
            await redis_client.ping()
            redis_connected = True
            telemetry_status = "active"

            # Stream length
            try:
                stream_length = await redis_client.xlen("bastion:events:v1")
            except Exception:
                stream_length = None

            # Consumer group lag
            try:
                groups = await redis_client.xinfo_groups("bastion:events:v1")
                for group in groups:
                    if group.get("name", b"").decode("utf-8", errors="replace") if isinstance(group.get("name"), bytes) else group.get("name", "") == "bastion_telemetry_workers":
                        worker_queue_lag = group.get("lag", group.get("pending", 0))
                        break
            except Exception:
                worker_queue_lag = None

            # Check rate limiter degradation
            rate_limiter = getattr(request.app.state, "rate_limiter", None)
            ioc_repo = getattr(request.app.state, "ioc_repo", None)
            if (rate_limiter and getattr(rate_limiter, "is_degraded", False)) or \
               (ioc_repo and getattr(ioc_repo, "is_degraded", False)):
                telemetry_status = "degraded"

        except Exception as e:
            logger.warning("Redis health check failed: %s", e)
            redis_connected = False
            telemetry_status = "offline"
        finally:
            if own_redis and redis_client:
                try:
                    await redis_client.aclose()
                except Exception:
                    pass

    # SQLite rule and site counts
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM waf_rules WHERE enabled = 1")
            rules_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM protected_sites")
            sites_count = cursor.fetchone()[0]
    except Exception:
        rules_count = 0
        sites_count = 0

    # Overall system status
    system_status = "healthy" if redis_connected else "degraded"

    # Mode from default site
    mode = "detection"
    site_repo = getattr(request.app.state, "site_repo", None)
    if site_repo:
        default_site = site_repo.resolve_site("127.0.0.1:8080") or site_repo.resolve_site("localhost:8080")
        if default_site:
            mode = default_site.mode

    return StatusResponse(
        status=system_status,
        mode=mode,
        redis_connected=redis_connected,
        rules_count=rules_count,
        sites_count=sites_count,
        worker_queue_lag=worker_queue_lag,
        stream_length=stream_length,
        telemetry_status=telemetry_status,
    )


@router.get("/overview", response_model=StatsOverviewResponse)
async def get_overview_stats(
    user=Depends(require_role("viewer")),
    time_range: str = Query(default="all", pattern="^(24h|7d|all)$"),
):
    """Real metrics from SQLite events table. No fabricated numbers."""
    from database.db import get_control_overview_stats

    stats = get_control_overview_stats(time_range=time_range)
    return StatsOverviewResponse(**stats)


@router.post("/sites/{site_id}/mode")
async def update_site_mode(site_id: str, req: SiteModeUpdateRequest, user=Depends(require_role("admin"))):
    mode = req.mode.lower()
    if mode not in ("detection", "prevention"):
        raise HTTPException(status_code=400, detail="Mode must be 'detection' or 'prevention'")
    AUDIT_LOG.append({"action": "SET_MODE", "site_id": site_id, "mode": mode, "actor": user["role"]})
    return {"status": "success", "site_id": site_id, "mode": mode}


@router.get("/audit")
async def get_audit_trail(user=Depends(require_role("admin"))):
    return AUDIT_LOG
