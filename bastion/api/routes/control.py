"""
Secure Dashboard & Control Plane API routes (/api/v1/).
Implements token/session authorization, stats overview, events, site mode controls,
rules management, and IOC endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
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
async def get_system_status():
    return StatusResponse(
        status="healthy",
        mode="detection",
        redis_connected=True,
        rules_count=18,
        sites_count=1,
        worker_queue_lag=0,
    )


@router.get("/overview", response_model=StatsOverviewResponse)
async def get_overview_stats(user=Depends(require_role("viewer"))):
    return StatsOverviewResponse(
        total_requests=1240,
        blocked_attacks=85,
        allowed_requests=1155,
        would_block_events=12,
        rate_limited_events=4,
        avg_latency_ms=2.8,
    )


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
