"""
Unit tests for RedisRateLimiter:
- Atomic Lua sliding window execution and sliding expiration
- IPv4 and IPv6 canonicalization
- Retry-After calculation
- Bounded input limits
- Fail-open degradation on Redis timeout/error
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
import redis.asyncio as aioredis
from bastion.storage.rate_limiter import RedisRateLimiter, RateLimitResult


def test_rate_limiter_canonicalize_dimension_value():
    # IPv4 standard and with whitespace
    assert RedisRateLimiter.canonicalize_dimension_value("ip", " 192.168.1.1 ") == "192.168.1.1"
    
    # IPv6 compressed vs uncompressed
    compressed = RedisRateLimiter.canonicalize_dimension_value("ip", "2001:db8::1")
    expanded = RedisRateLimiter.canonicalize_dimension_value("ip", "2001:0db8:0000:0000:0000:0000:0000:0001")
    assert compressed == expanded
    assert compressed == "2001:db8::1"

    # Non-IP dimension should just strip whitespace
    assert RedisRateLimiter.canonicalize_dimension_value("token", "  my-api-token  ") == "my-api-token"


@pytest.mark.asyncio
async def test_rate_limiter_fail_open_when_no_redis():
    limiter = RedisRateLimiter(None)
    res = await limiter.evaluate_limit("site1", "ip", "10.0.0.1", limit=10, window_seconds=60)
    assert res.allowed is True
    assert res.remaining == 10
    assert res.retry_after == 0
    assert limiter.is_degraded is False


@pytest.mark.asyncio
async def test_rate_limiter_lua_atomic_execution():
    fake_redis = AsyncMock()
    # Mock EVAL return [allowed, remaining, retry_after]
    fake_redis.eval = AsyncMock(return_value=[1, 4, 0])

    limiter = RedisRateLimiter(fake_redis)
    res = await limiter.evaluate_limit(
        site_id="site-test",
        dimension="ip",
        value="1.2.3.4",
        limit=5,
        window_seconds=60,
        request_id="req-123",
    )
    assert res.allowed is True
    assert res.remaining == 4
    assert res.retry_after == 0
    assert fake_redis.eval.called


@pytest.mark.asyncio
async def test_rate_limiter_limit_exceeded_with_retry_after():
    fake_redis = AsyncMock()
    # Mock EVAL return for over limit: [0, 0, 42]
    fake_redis.eval = AsyncMock(return_value=[0, 0, 42])

    limiter = RedisRateLimiter(fake_redis)
    res = await limiter.evaluate_limit(
        site_id="site-test",
        dimension="ip",
        value="1.2.3.4",
        limit=5,
        window_seconds=60,
    )
    assert res.allowed is False
    assert res.remaining == 0
    assert res.retry_after == 42
    assert limiter.limited_count == 1


@pytest.mark.asyncio
async def test_rate_limiter_fail_open_on_timeout():
    fake_redis = AsyncMock()
    # Simulate a Redis timeout
    fake_redis.eval = AsyncMock(side_effect=asyncio.TimeoutError("Redis timed out"))

    limiter = RedisRateLimiter(fake_redis, timeout_seconds=0.01)
    res = await limiter.evaluate_limit(
        site_id="site-test",
        dimension="ip",
        value="1.2.3.4",
        limit=10,
        window_seconds=60,
    )
    # Must fail open: allow request, mark degraded
    assert res.allowed is True
    assert res.remaining == 10
    assert res.retry_after == 0
    assert limiter.is_degraded is True
    assert limiter.error_count == 1


@pytest.mark.asyncio
async def test_rate_limiter_fail_open_on_redis_error():
    fake_redis = AsyncMock()
    fake_redis.eval = AsyncMock(side_effect=aioredis.ConnectionError("Connection lost"))

    limiter = RedisRateLimiter(fake_redis)
    res = await limiter.evaluate_limit(
        site_id="site-test",
        dimension="ip",
        value="1.2.3.4",
        limit=10,
        window_seconds=60,
    )
    # Must fail open
    assert res.allowed is True
    assert res.remaining == 10
    assert limiter.is_degraded is True
    assert limiter.error_count == 1


@pytest.mark.asyncio
async def test_rate_limiter_real_redis_sliding_window():
    # If local redis is running, run real integration test against redis
    try:
        r = aioredis.from_url("redis://127.0.0.1:6379/0")
        await r.ping()
    except Exception:
        pytest.skip("Local Redis server not accessible")

    limiter = RedisRateLimiter(r)
    site_id = "test-real-rl"
    dim = "ip"
    ip = "192.168.100.200"
    key = limiter._make_key(site_id, dim, ip)

    try:
        await r.delete(key)
        # Limit: 2 requests per 5 seconds
        res1 = await limiter.evaluate_limit(site_id, dim, ip, limit=2, window_seconds=5)
        assert res1.allowed is True
        assert res1.remaining == 1

        res2 = await limiter.evaluate_limit(site_id, dim, ip, limit=2, window_seconds=5)
        assert res2.allowed is True
        assert res2.remaining == 0

        # 3rd request must be blocked
        res3 = await limiter.evaluate_limit(site_id, dim, ip, limit=2, window_seconds=5)
        assert res3.allowed is False
        assert res3.remaining == 0
        assert res3.retry_after > 0
    finally:
        await r.delete(key)
        await r.aclose()
