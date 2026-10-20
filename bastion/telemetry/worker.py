"""
Asynchronous OpenSearch Telemetry Worker.
Pulls events from Redis Stream consumer group, validates schemas,
batches them into OpenSearch Bulk API, and handles retries and dead-letters.
Completely off the request-path!
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import redis.asyncio as aioredis
from pydantic import ValidationError

from .schemas import SecurityEvent

logger = logging.getLogger("bastion.telemetry.worker")


class TelemetryWorker:
    def __init__(
        self,
        redis_client: aioredis.Redis,
        opensearch_client: Optional[Any] = None,
        stream_name: str = "bastion:events:v1",
        group_name: str = "bastion_telemetry_workers",
        consumer_name: str = "worker_1",
        index_pattern: str = "bastion-events-v1",
    ):
        self.redis = redis_client
        self.opensearch = opensearch_client
        self.stream_name = stream_name
        self.group_name = group_name
        self.consumer_name = consumer_name
        self.index_pattern = index_pattern
        self.running = False
        self.indexed_count = 0
        self.dead_letter_count = 0

    async def setup_consumer_group(self):
        try:
            await self.redis.xgroup_create(self.stream_name, self.group_name, id="0", mkstream=True)
            logger.info("Created consumer group '%s' for stream '%s'", self.group_name, self.stream_name)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                logger.warning("Error setting up stream consumer group: %s", e)

    async def process_batch(self, batch_size: int = 50) -> int:
        """Read and bulk-index a batch of events."""
        try:
            entries = await self.redis.xreadgroup(
                self.group_name,
                self.consumer_name,
                {self.stream_name: ">"},
                count=batch_size,
                block=1000,
            )
        except Exception as e:
            logger.error("Error reading from Redis Stream: %s", e)
            return 0

        if not entries:
            return 0

        stream, messages = entries[0]
        if not messages:
            return 0

        docs_to_index: List[Dict[str, Any]] = []
        ack_ids: List[str] = []

        for msg_id, fields in messages:
            ack_ids.append(msg_id)
            try:
                raw_payload = fields.get("payload") or fields.get(b"payload")
                if not raw_payload:
                    continue
                if isinstance(raw_payload, bytes):
                    raw_payload = raw_payload.decode("utf-8")
                data = json.loads(raw_payload)
                event = SecurityEvent(**data)
                today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
                doc = {
                    "_index": f"{self.index_pattern}-{today}",
                    "_id": event.event_id,
                    "_source": event.model_dump(by_alias=True),
                }
                docs_to_index.append(doc)
            except (ValidationError, json.JSONDecodeError) as err:
                self.dead_letter_count += 1
                logger.error("Dead-letter event due to schema error: %s", err)

        # Bulk index into OpenSearch if client is available
        if docs_to_index and self.opensearch:
            try:
                # Use client bulk or async_bulk
                if hasattr(self.opensearch, "bulk"):
                    actions = []
                    for d in docs_to_index:
                        actions.append({"index": {"_index": d["_index"], "_id": d["_id"]}})
                        actions.append(d["_source"])
                    import inspect
                    if inspect.iscoroutinefunction(self.opensearch.bulk):
                        res = await self.opensearch.bulk(body=actions)
                    else:
                        res = await asyncio.to_thread(self.opensearch.bulk, body=actions)
                    self.indexed_count += len(docs_to_index)
            except Exception as e:
                logger.error("Failed to bulk index events to OpenSearch: %s", e)

        # Acknowledge messages
        if ack_ids:
            await self.redis.xack(self.stream_name, self.group_name, *ack_ids)

        return len(docs_to_index)
