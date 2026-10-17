"""
Pydantic schemas for the control plane and dashboard REST API.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class StatusResponse(BaseModel):
    status: str
    mode: str
    redis_connected: bool
    rules_count: int
    sites_count: int
    worker_queue_lag: int = 0


class StatsOverviewResponse(BaseModel):
    total_requests: int
    blocked_attacks: int
    allowed_requests: int
    would_block_events: int
    rate_limited_events: int
    avg_latency_ms: float


class RuleToggleRequest(BaseModel):
    rule_id: str
    enabled: bool


class SiteModeUpdateRequest(BaseModel):
    mode: str  # "detection" | "prevention"


class IOCCreateRequest(BaseModel):
    ip: str
    source: str = "Admin"
    reason: str
    ttl_seconds: int = 86400
    confidence: float = 1.0


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    status: str
    token: str
    role: str
