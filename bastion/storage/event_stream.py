"""
Asynchronous Redis Streams event transport.
Enqueues compact security events to a stream without blocking on OpenSearch.
"""

import json
import logging
from typing import Any, Dict, Optional
import redis.asyncio as aioredis

logger = logging.getLogger("bastion.storage.event_stream")


class RedisStreamPublisher:
    def __init__(self, redis_client: Optional[aioredis.Redis], stream_name: str = "bastion:events:v1"):
        self.redis = redis_client
        self.stream_name = stream_name

    async def publish_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Publish a serialized SecurityEvent to the Redis stream."""
        if not self.redis:
            return None
        try:
            entry = {"payload": json.dumps(event_data)}
            # Max length cap on stream to prevent unbounded memory growth
            entry_id = await self.redis.xadd(self.stream_name, entry, maxlen=50_000, approximate=True)
            return entry_id
        except Exception as e:
            logger.error("Failed to enqueue security event to Redis stream: %s", e)
            return None
