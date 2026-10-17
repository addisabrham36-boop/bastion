"""
Unit tests for Milestone 6: Redis IOC repository (individual TTLs, canonical IPs),
and RateLimiter behavior with fakes/mocks.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from bastion.storage.ioc_repository import RedisIOCRepository
from bastion.storage.rate_limiter import RedisRateLimiter


def test_ip_canonicalization():
    assert RedisIOCRepository.canonicalize_ip(" 192.168.1.1 ") == "192.168.1.1"
    assert RedisIOCRepository.canonicalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"

    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_ip("not-an-ip")


@pytest.mark.asyncio
async def test_ioc_repository_per_indicator_key_and_ttl():
    mock_redis = AsyncMock()
    repo = RedisIOCRepository(mock_redis)

    # 1. Add valid IPv4 IOC
    success = await repo.add_ip_ioc(
        ip="203.0.113.10",
        source="ThreatFeedA",
        reason="Malicious scanner",
        ttl_seconds=3600,
    )
    assert success is True
    # Verify set called with specific key and individual TTL
    mock_redis.set.assert_called_once()
    args, kwargs = mock_redis.set.call_args
    assert args[0] == "bastion:ioc:v1:ip:203.0.113.10"
    assert kwargs["ex"] == 3600

    # 2. Invalid IP rejected safely
    assert await repo.add_ip_ioc("invalid.ip", "feed", "bad") is False


@pytest.mark.asyncio
async def test_rate_limiter_lua_execution():
    mock_redis = AsyncMock()
    # Mock Redis returning [allowed=1, remaining=59, retry_after=0]
    mock_redis.eval.return_value = [1, 59, 0]

    limiter = RedisRateLimiter(mock_redis)
    result = await limiter.evaluate_limit(
        site_id="demo",
        dimension="ip",
        value="127.0.0.1",
        limit=60,
        window_seconds=60,
    )
    assert result.allowed is True
    assert result.remaining == 59
    assert result.retry_after == 0
    mock_redis.eval.assert_called_once()
