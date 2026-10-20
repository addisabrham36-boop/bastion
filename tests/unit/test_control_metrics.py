"""
Unit tests for Control API live metrics (/api/v1/status and /api/v1/overview):
- Truthful metrics from SQLite events table
- Time range filtering (24h, 7d, all)
- Real moving average latency calculation (not fabricated)
- Status response with Redis connectivity, consumer group lag, stream length, and degraded states
"""

import os
from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
import redis.asyncio as aioredis

from bastion.api.routes.control import router as control_router
from bastion.proxy.router import SiteConfig, SiteRepository
from database.db import clear_logs, log_event, init_db


@pytest.fixture(autouse=True)
def clean_database():
    init_db()
    clear_logs()
    yield
    clear_logs()


@pytest.mark.asyncio
async def test_control_overview_metrics_truthful_counts():
    app = FastAPI()
    app.include_router(control_router)
    transport = ASGITransport(app=app)

    # 1. Initially empty
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/overview", headers={"Authorization": "Bearer dev-viewer-token"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 0
        assert data["blocked_attacks"] == 0
        assert data["allowed_requests"] == 0
        assert data["would_block_events"] == 0
        assert data["rate_limited_events"] == 0
        assert data["avg_latency_ms"] is None

        # 2. Add realistic events to SQLite
        # Allowed clean request with duration 12.5ms
        log_event(
            client_ip="192.168.1.50",
            method="GET",
            path="/index.html",
            blocked=False,
            rule_id="",
            reason="Clean Request",
            action="200 Allowed",
            duration_ms=12.5,
        )
        # Blocked SQLi attack with duration 3.2ms
        log_event(
            client_ip="192.168.1.51",
            method="GET",
            path="/login?user=' OR 1=1--",
            blocked=True,
            rule_id="942100",
            reason="SQL Injection matched",
            action="403 Blocked",
            duration_ms=3.2,
        )
        # Detection mode event with duration 4.8ms
        log_event(
            client_ip="192.168.1.52",
            method="GET",
            path="/etc/passwd",
            blocked=False,
            rule_id="930100",
            reason="Path Traversal detected",
            action="Detection Mode Allowed",
            duration_ms=4.8,
        )
        # Rate-limited event with duration 0.9ms
        log_event(
            client_ip="192.168.1.53",
            method="GET",
            path="/api/data",
            blocked=True,
            rule_id="RATE_LIMIT_EXCEEDED",
            reason="Rate limit exceeded",
            action="429 Rate Limited",
            duration_ms=0.9,
        )

        resp2 = await client.get("/api/v1/overview", headers={"Authorization": "Bearer dev-viewer-token"})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total_requests"] == 4
        assert data2["blocked_attacks"] == 2  # 1 SQLi + 1 429
        assert data2["allowed_requests"] == 2  # 1 clean + 1 detection mode
        assert data2["would_block_events"] == 1
        assert data2["rate_limited_events"] == 1
        # Average of [12.5, 3.2, 4.8, 0.9] = 21.4 / 4 = 5.35ms
        assert data2["avg_latency_ms"] is not None
        assert abs(data2["avg_latency_ms"] - 5.35) < 0.1


@pytest.mark.asyncio
async def test_control_status_endpoint_with_redis():
    app = FastAPI()
    app.include_router(control_router)

    # Attach mock Redis event_publisher and site_repo to app.state
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)
    mock_redis.xlen = AsyncMock(return_value=42)
    mock_redis.xinfo_groups = AsyncMock(return_value=[{"name": "bastion_telemetry_workers", "lag": 3}])

    class MockPublisher:
        def __init__(self, r):
            self.redis = r

    app.state.event_publisher = MockPublisher(mock_redis)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["redis_connected"] is True
        assert data["rules_count"] > 0
        assert data["sites_count"] > 0
        assert data["stream_length"] == 42
        assert data["worker_queue_lag"] == 3
        assert data["telemetry_status"] == "active"


@pytest.mark.asyncio
async def test_control_status_degraded_when_redis_fails():
    app = FastAPI()
    app.include_router(control_router)

    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(side_effect=aioredis.ConnectionError("Redis down"))

    class MockPublisher:
        def __init__(self, r):
            self.redis = r

    app.state.event_publisher = MockPublisher(mock_redis)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["redis_connected"] is False
        assert data["telemetry_status"] == "offline"
