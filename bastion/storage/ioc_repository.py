"""
Redis IOC repository fixing the blueprint expiry bug:
Stores each IOC as an individual key with an individual TTL.
Canonicalizes and validates IPv4 and IPv6 addresses.
"""

from datetime import datetime, timezone
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional
import redis.asyncio as aioredis

logger = logging.getLogger("bastion.storage.ioc")


class RedisIOCRepository:
    """Manages threat indicators in Redis with individual key TTLs."""

    def __init__(self, redis_client: Optional[aioredis.Redis]):
        self.redis = redis_client

    @staticmethod
    def canonicalize_ip(ip_str: str) -> str:
        """Validate and return canonical representation of IPv4 or IPv6."""
        addr = ipaddress.ip_address(ip_str.strip())
        return str(addr)

    def _key_for_ip(self, canonical_ip: str) -> str:
        return f"bastion:ioc:v1:ip:{canonical_ip}"

    async def add_ip_ioc(
        self,
        ip: str,
        source: str,
        reason: str,
        ttl_seconds: int = 86400,
        confidence: float = 1.0,
    ) -> bool:
        """Add an IP indicator with an individual key and TTL."""
        if not self.redis:
            return False
        try:
            canonical_ip = self.canonicalize_ip(ip)
            key = self._key_for_ip(canonical_ip)
            payload = {
                "ip": canonical_ip,
                "source": source,
                "reason": reason,
                "confidence": confidence,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": ttl_seconds,
            }
            await self.redis.set(key, json.dumps(payload), ex=ttl_seconds)
            return True
        except ValueError as e:
            logger.warning("Invalid IP address rejected: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to add IOC to Redis: %s", e)
            return False

    async def check_ip_ioc(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up active IOC record for the given IP."""
        if not self.redis:
            return None
        try:
            canonical_ip = self.canonicalize_ip(ip)
            key = self._key_for_ip(canonical_ip)
            raw = await self.redis.get(key)
            if raw:
                return json.loads(raw)
            return None
        except ValueError:
            return None
        except Exception as e:
            logger.error("Failed to check IOC in Redis: %s", e)
            return None

    async def remove_ip_ioc(self, ip: str) -> bool:
        if not self.redis:
            return False
        try:
            canonical_ip = self.canonicalize_ip(ip)
            key = self._key_for_ip(canonical_ip)
            deleted = await self.redis.delete(key)
            return deleted > 0
        except Exception:
            return False
