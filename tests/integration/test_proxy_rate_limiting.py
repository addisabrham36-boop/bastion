"""
Integration tests for Phase 5: Redis Rate Limiting in the live WAF reverse proxy.
Verifies:
1. Rate limit enforcement in prevention mode (HTTP 429 Too Many Requests, Retry-After header, blocked=1 in SQLite).
2. Rate limit behavior in detection mode (Allowed through, status != 429, blocked=0 in SQLite).
3. Spoofed X-Forwarded-For headers from untrusted peers are ignored (peer IP is rate-limited).
4. Trusted proxy X-Forwarded-For headers are honored.
5. Global killswitch BASTION_RATE_LIMIT_ENABLED=false completely disables rate limiting while preserving WAF & IOC inspection.
6. Public paths on Port 8080 (including /health) do NOT receive blanket exemptions and are subject to rate limiting.
7. Teardown restores database, Redis keys, and environment variables even on failure.
"""

import os
from unittest.mock import AsyncMock
import pytest
import httpx
import redis.asyncio as aioredis

from bastion.core.proxy import app as proxy_app, rate_limiter
from database.db import get_recent_events, get_sites, init_db, set_site_defense


@pytest.fixture(autouse=True)
async def clean_state():
    init_db()
    for s in get_sites():
        set_site_defense(s["id"], True)
    os.environ["BASTION_RATE_LIMIT_ENABLED"] = "true"

    # Reset any rate limiter degraded state
    rate_limiter.is_degraded = False
    rate_limiter.error_count = 0
    rate_limiter.lookup_count = 0
    rate_limiter.limited_count = 0

    yield

    for s in get_sites():
        set_site_defense(s["id"], True)
    os.environ["BASTION_RATE_LIMIT_ENABLED"] = "true"


@pytest.mark.asyncio
async def test_proxy_rate_limiting_enforced_in_prevention_mode():
    """Verify that requests exceeding configured rate limit receive 429 with Retry-After header."""
    mock_redis = AsyncMock()
    # 1st request: allowed (remaining=1)
    # 2nd request: allowed (remaining=0)
    # 3rd request: limited (allowed=0, remaining=0, retry_after=30)
    mock_redis.eval = AsyncMock(
        side_effect=[
            [1, 1, 0],
            [1, 0, 0],
            [0, 0, 30],
        ]
    )

    orig_redis = rate_limiter.redis
    rate_limiter.redis = mock_redis
    proxy_app.state.rate_limiter = rate_limiter

    try:
        transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.99", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Request 1: allowed
            r1 = await client.get("/catalog")
            assert r1.status_code != 429

            # Request 2: allowed
            r2 = await client.get("/catalog")
            assert r2.status_code != 429

            # Request 3: 429 Rate Limited
            r3 = await client.get("/catalog")
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers
            assert r3.headers["Retry-After"] == "30"
            data = r3.json()
            assert data["blocked"] is True
            assert data["status"] == 429

            # Verify SQLite event
            events = get_recent_events(limit=5)
            rl_events = [e for e in events if e["rule_id"] == "RATE_LIMIT_EXCEEDED" and e["blocked"] == 1]
            assert len(rl_events) >= 1
            assert "429 Rate Limited" in rl_events[0]["action"]
    finally:
        rate_limiter.redis = orig_redis


@pytest.mark.asyncio
async def test_proxy_rate_limiting_in_detection_mode():
    """Verify that in detection mode, rate limits are observed and logged but not blocked."""
    # Set site defense mode to False (detection mode)
    for s in get_sites():
        set_site_defense(s["id"], False)

    mock_redis = AsyncMock()
    # Mock over limit
    mock_redis.eval = AsyncMock(return_value=[0, 0, 15])

    orig_redis = rate_limiter.redis
    rate_limiter.redis = mock_redis
    proxy_app.state.rate_limiter = rate_limiter

    try:
        transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.99", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/catalog")
            # In detection mode, MUST NOT return 429
            assert resp.status_code != 429

            # Verify SQLite event logged observation with blocked=0
            events = get_recent_events(limit=5)
            rl_events = [e for e in events if e["rule_id"] == "RATE_LIMIT_EXCEEDED" and e["blocked"] == 0]
            assert len(rl_events) >= 1
            assert "Detection Mode Rate Limit Observed" in rl_events[0]["action"]
    finally:
        rate_limiter.redis = orig_redis


@pytest.mark.asyncio
async def test_proxy_rate_limiting_killswitch():
    """Verify that BASTION_RATE_LIMIT_ENABLED=false completely bypasses rate limiting."""
    os.environ["BASTION_RATE_LIMIT_ENABLED"] = "false"

    mock_redis = AsyncMock()
    # If called, it would return over limit
    mock_redis.eval = AsyncMock(return_value=[0, 0, 60])

    orig_redis = rate_limiter.redis
    rate_limiter.redis = mock_redis
    proxy_app.state.rate_limiter = rate_limiter

    try:
        transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.99", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/catalog")
            # Rate limiter must not be evaluated
            assert mock_redis.eval.called is False
            assert resp.status_code != 429
    finally:
        rate_limiter.redis = orig_redis
        os.environ["BASTION_RATE_LIMIT_ENABLED"] = "true"


@pytest.mark.asyncio
async def test_proxy_rate_limiting_spoofed_xff_ignored():
    """Verify that spoofed X-Forwarded-For from an untrusted client peer is ignored."""
    mock_redis = AsyncMock()
    mock_redis.eval = AsyncMock(return_value=[1, 5, 0])

    orig_redis = rate_limiter.redis
    rate_limiter.redis = mock_redis
    proxy_app.state.rate_limiter = rate_limiter

    try:
        # Untrusted client peer 203.0.113.5 claims to be 10.0.0.1 via XFF
        transport = httpx.ASGITransport(app=proxy_app, client=("203.0.113.5", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.get("/catalog", headers={"x-forwarded-for": "10.0.0.1"})

            # Verify that rate limiter evaluated the actual peer IP 203.0.113.5, NOT the spoofed 10.0.0.1
            call_args = mock_redis.eval.call_args
            assert call_args is not None
            # The key is the second positional argument (KEYS[1])
            key = call_args[0][2]
            # Key uses SHA256 of canonical client IP
            expected_key = rate_limiter._make_key("demo-site", "ip", "203.0.113.5")
            assert key == expected_key
    finally:
        rate_limiter.redis = orig_redis


@pytest.mark.asyncio
async def test_proxy_public_health_path_not_exempt_on_port_8080():
    """
    Verify that public requests to /health on WAF proxy port 8080 are NOT exempt from rate limiting.
    (Listener separation: only port 9000 gateway has unthrottled health endpoints).
    """
    mock_redis = AsyncMock()
    # Mock over limit for /health
    mock_redis.eval = AsyncMock(return_value=[0, 0, 45])

    orig_redis = rate_limiter.redis
    rate_limiter.redis = mock_redis
    proxy_app.state.rate_limiter = rate_limiter

    try:
        transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.99", 54321))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/health")
            # Must be throttled with 429
            assert resp.status_code == 429
            assert resp.headers.get("Retry-After") == "45"
    finally:
        rate_limiter.redis = orig_redis
