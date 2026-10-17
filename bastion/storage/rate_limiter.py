"""
Distributed atomic rate limiter using Redis sorted sets (sliding-window log)
executed via an atomic Lua script.
"""

from dataclasses import dataclass
import hashlib
import time
from typing import Optional
import redis.asyncio as aioredis

LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clear_before = now - window

-- 1. Remove entries older than the window
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)

-- 2. Count current entries in window
local current_requests = redis.call('ZCARD', key)

if current_requests < limit then
    -- Add unique request entry
    redis.call('ZADD', key, now, ARGV[4])
    redis.call('EXPIRE', key, math.ceil(window))
    return {1, limit - current_requests - 1, 0}
else
    -- Over limit: calculate retry after
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if #oldest > 1 then
        retry_after = math.max(1, math.ceil(tonumber(oldest[2]) + window - now))
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
    def __init__(self, redis_client: Optional[aioredis.Redis]):
        self.redis = redis_client
        self._script_sha = None

    def _make_key(self, site_id: str, dimension: str, value: str) -> str:
        # Hash value to maintain bounded key length
        val_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
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
        if not self.redis:
            # If Redis unavailable, allow gracefully in dev, or apply local fallback
            return RateLimitResult(allowed=True, remaining=limit, retry_after=0)

        key = self._make_key(site_id, dimension, value)
        now = time.time()
        member_id = f"{now}:{request_id}"

        try:
            res = await self.redis.eval(
                LUA_SLIDING_WINDOW,
                1,
                key,
                str(now),
                str(window_seconds),
                str(limit),
                member_id,
            )
            allowed = bool(res[0] == 1)
            remaining = int(res[1])
            retry_after = int(res[2])
            return RateLimitResult(allowed=allowed, remaining=remaining, retry_after=retry_after)
        except Exception:
            return RateLimitResult(allowed=True, remaining=limit, retry_after=0)
