"""
Redis client lifecycle and connection management with graceful degradation.
"""

import logging
from typing import Optional
import redis.asyncio as aioredis
from ..settings import Settings

logger = logging.getLogger("bastion.storage.redis")


class RedisService:
    def __init__(self, url: str):
        self.url = url
        self._client: Optional[aioredis.Redis] = None

    async def connect(self):
        try:
            self._client = aioredis.from_url(
                self.url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
            await self._client.ping()
            logger.info("Connected to Redis successfully.")
        except Exception as e:
            logger.warning("Redis connection failed (%s); operating in degraded mode.", e)
            self._client = None

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> Optional[aioredis.Redis]:
        return self._client

    @property
    def is_available(self) -> bool:
        return self._client is not None
