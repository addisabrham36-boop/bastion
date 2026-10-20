"""
Distributed atomic rate limiter using Redis sorted sets (sliding-window log)
executed via an atomic Lua script with server-side time precision.
"""

import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
from typing import Optional
import uuid
import redis.asyncio as aioredis

logger = logging.getLogger("bastion.storage.rate_limiter")

LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local request_id = ARGV[3] or ''

-- 1. Authoritative Redis server time (seconds + microseconds)
local time_arr = redis.call('TIME')
local now_sec = tonumber(time_arr[1])
local now_usec = tonumber(time_arr[2])
local now = now_sec + (now_usec / 1000000)
local clear_before = now - window

-- 2. Remove expired entries strictly before the active sliding window
redis.call('ZREMRANGEBYSCORE', key, '-inf', clear_before)

-- 3. Count current entries in window
local current_requests = redis.call('ZCARD', key)

if current_requests < limit then
    -- Unique member ID prevents collisions within the same microsecond
    local member_id = tostring(now_sec) .. '.' .. tostring(now_usec) .. ':' .. request_id
    redis.call('ZADD', key, now, member_id)
    redis.call('EXPIRE', key, math.ceil(window))
    return {1, limit - current_requests - 1, 0}
else
    -- Over limit: read oldest score in active window for retry calculation
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if #oldest > 1 then
        local oldest_score = tonumber(oldest[2])
        retry_after = math.max(1, math.ceil(oldest_score + window - now))
    end
    return {0, 0, retry_after}
end
"""


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int


class RedisRateLimiter:
    def __init__(self, redis_client: Optional[aioredis.Redis], timeout_seconds: Optional[float] = None):
        self.redis = redis_client
        if timeout_seconds is None:
            try:
                from ..settings import get_settings
                self.timeout_seconds = get_settings().bastion_rate_limit_timeout_seconds
            except Exception:
                self.timeout_seconds = 0.1
        else:
            self.timeout_seconds = timeout_seconds
        self.lookup_count: int = 0
        self.limited_count: int = 0
        self.error_count: int = 0
        self.is_degraded: bool = False

    @staticmethod
    def canonicalize_dimension_value(dimension: str, value: str) -> str:
        """Canonicalize IP addresses to ensure consistent key hashing for IPv4 and IPv6."""
        clean = value.strip()
        if dimension in ("ip", "client_ip") or "ip" in dimension:
            try:
                addr = ipaddress.ip_address(clean)
                return str(addr)
            except ValueError:
                pass
        return clean

    def _make_key(self, site_id: str, dimension: str, value: str) -> str:
        canonical_val = self.canonicalize_dimension_value(dimension, value)
        val_hash = hashlib.sha256(canonical_val.encode("utf-8")).hexdigest()[:16]
        return f"bastion:rl:v1:{site_id}:{dimension}:{val_hash}"

    async def evaluate_limit(
        self,
        site_id: str,
        dimension: str,
        value: str,
        limit: int = 60,
        window_seconds: int = 60,
        request_id: str = "",
    ) -> RateLimitResult:
        self.lookup_count += 1
        if not self.redis:
            # If Redis unavailable, fail open gracefully
            return RateLimitResult(allowed=True, remaining=limit, retry_after=0)

        # Enforce input bounds
        bounded_limit = max(1, min(limit, 100_000))
        bounded_window = max(1, min(window_seconds, 86_400))

        key = self._make_key(site_id, dimension, value)
        req_id = request_id or str(uuid.uuid4())

        try:
            res = await asyncio.wait_for(
                self.redis.eval(
                    LUA_SLIDING_WINDOW,
                    1,
                    key,
                    str(bounded_window),
                    str(bounded_limit),
                    req_id,
                ),
                timeout=self.timeout_seconds,
            )
            allowed = bool(res[0] == 1)
            remaining = int(res[1])
            retry_after = int(res[2])
            if not allowed:
                self.limited_count += 1
            return RateLimitResult(allowed=allowed, remaining=remaining, retry_after=retry_after)
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as exc:
            self.error_count += 1
            self.is_degraded = True
            err_name = type(exc).__name__
            err_msg = str(exc) or "timeout"
            logger.warning(
                "Rate limiter encountered %s (%s); operating in fail-open mode",
                err_name,
                err_msg,
            )
            return RateLimitResult(allowed=True, remaining=bounded_limit, retry_after=0)
