"""
Redis IOC repository fixing the blueprint expiry bug:
Stores each IOC as an individual key with an individual TTL.
Canonicalizes and validates IPv4, IPv6, Domain, and URI/Path indicators.
"""

import asyncio
from datetime import datetime, timezone
import ipaddress
import json
import logging
import posixpath
import re
from typing import Any, Dict, List, Optional
import redis.asyncio as aioredis

logger = logging.getLogger("bastion.storage.ioc")

_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class RedisIOCRepository:
    """
    Manages threat indicators in Redis with individual key TTLs,
    bounded query timeouts, and multi-type indicator support (IP, Domain, Path).
    """

    def __init__(self, redis_client: Optional[aioredis.Redis], default_timeout: float = 0.05):
        self.redis = redis_client
        self.default_timeout = default_timeout
        self.lookup_count: int = 0
        self.match_count: int = 0
        self.error_count: int = 0
        self.is_degraded: bool = False

    # -------------------------------------------------------------------------
    # IP Indicators
    # -------------------------------------------------------------------------

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
                "type": "ip",
                "ip": canonical_ip,
                "source": source,
                "reason": reason,
                "confidence": confidence,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": ttl_seconds,
            }
            await asyncio.wait_for(
                self.redis.set(key, json.dumps(payload), ex=ttl_seconds),
                timeout=self.default_timeout,
            )
            return True
        except ValueError as e:
            logger.warning("Invalid IP address rejected: %s", e)
            return False
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.error("Failed to add IP IOC to Redis: %s", e)
            return False

    async def check_ip_ioc(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up active IOC record for the given IP with bounded timeout."""
        if not self.redis:
            return None
        self.lookup_count += 1
        try:
            canonical_ip = self.canonicalize_ip(ip)
            key = self._key_for_ip(canonical_ip)
            raw = await asyncio.wait_for(
                self.redis.get(key),
                timeout=self.default_timeout,
            )
            if raw:
                self.match_count += 1
                return json.loads(raw)
            return None
        except ValueError:
            return None
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.warning("Failed to check IP IOC in Redis (degraded mode active): %s", e)
            return None

    async def remove_ip_ioc(self, ip: str) -> bool:
        if not self.redis:
            return False
        try:
            canonical_ip = self.canonicalize_ip(ip)
            key = self._key_for_ip(canonical_ip)
            deleted = await asyncio.wait_for(
                self.redis.delete(key),
                timeout=self.default_timeout,
            )
            return deleted > 0
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Domain Indicators
    # -------------------------------------------------------------------------

    @staticmethod
    def canonicalize_domain(domain_str: str) -> str:
        """
        Normalize domain name:
        - Strip leading/trailing whitespace
        - Remove port if present
        - Strip trailing dot
        - Lowercase
        - Normalize IDNA representation
        """
        raw = domain_str.strip()
        if not raw:
            raise ValueError("Domain cannot be empty")
        # Strip port
        if ":" in raw:
            raw = raw.split(":")[0]
        raw = raw.rstrip(".").lower()
        try:
            # Normalize to ASCII punycode via IDNA
            ascii_domain = raw.encode("idna").decode("ascii")
        except Exception as e:
            raise ValueError(f"Invalid IDNA domain representation: {e}")

        # Check label structure (allow localhost for controlled testing)
        if ascii_domain != "localhost" and not _DOMAIN_REGEX.match(ascii_domain):
            raise ValueError(f"Malformed domain name: '{ascii_domain}'")
        return ascii_domain

    def _key_for_domain(self, canonical_domain: str) -> str:
        return f"bastion:ioc:v1:domain:{canonical_domain}"

    async def add_domain_ioc(
        self,
        domain: str,
        source: str,
        reason: str,
        ttl_seconds: int = 86400,
        confidence: float = 1.0,
        allow_subdomains: bool = False,
    ) -> bool:
        """Add a domain indicator with an individual key and TTL."""
        if not self.redis:
            return False
        try:
            canonical = self.canonicalize_domain(domain)
            key = self._key_for_domain(canonical)
            payload = {
                "type": "domain",
                "domain": canonical,
                "source": source,
                "reason": reason,
                "confidence": confidence,
                "allow_subdomains": allow_subdomains,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": ttl_seconds,
            }
            await asyncio.wait_for(
                self.redis.set(key, json.dumps(payload), ex=ttl_seconds),
                timeout=self.default_timeout,
            )
            return True
        except ValueError as e:
            logger.warning("Invalid domain indicator rejected: %s", e)
            return False
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.error("Failed to add domain IOC to Redis: %s", e)
            return False

    async def check_domain_ioc(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Look up active domain IOC.
        Performs exact match first, then checks parent domains if allow_subdomains is configured.
        Strict boundary enforcement: 'evil-example.com' never matches 'example.com'.
        """
        if not self.redis:
            return None
        self.lookup_count += 1
        try:
            canonical = self.canonicalize_domain(domain)
            # 1. Exact match lookup
            key = self._key_for_domain(canonical)
            raw = await asyncio.wait_for(
                self.redis.get(key),
                timeout=self.default_timeout,
            )
            if raw:
                self.match_count += 1
                return json.loads(raw)

            # 2. Check parent domains with subdomain matching enabled
            parts = canonical.split(".")
            for i in range(1, len(parts)):
                parent_domain = ".".join(parts[i:])
                if "." not in parent_domain and parent_domain != "localhost":
                    # Do not check top-level domains alone (e.g., .com)
                    continue
                parent_key = self._key_for_domain(parent_domain)
                parent_raw = await asyncio.wait_for(
                    self.redis.get(parent_key),
                    timeout=self.default_timeout,
                )
                if parent_raw:
                    record = json.loads(parent_raw)
                    if record.get("allow_subdomains", False):
                        self.match_count += 1
                        return record

            return None
        except ValueError:
            return None
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.warning("Failed to check domain IOC in Redis: %s", e)
            return None

    async def remove_domain_ioc(self, domain: str) -> bool:
        if not self.redis:
            return False
        try:
            canonical = self.canonicalize_domain(domain)
            key = self._key_for_domain(canonical)
            deleted = await asyncio.wait_for(
                self.redis.delete(key),
                timeout=self.default_timeout,
            )
            return deleted > 0
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Path Indicators
    # -------------------------------------------------------------------------

    @staticmethod
    def canonicalize_path(path_str: str) -> str:
        """
        Canonicalize URI path indicator:
        - Strip whitespace
        - Ensure leading slash
        - Resolve dot segments via POSIX normalization
        """
        clean = path_str.strip()
        if not clean:
            return "/"
        if not clean.startswith("/"):
            clean = "/" + clean
        # Strip query string if provided in path indicator
        if "?" in clean:
            clean = clean.split("?")[0]
        # Normalize relative traversal
        norm = posixpath.normpath(clean)
        # Ensure preserved leading slash
        if not norm.startswith("/"):
            norm = "/" + norm
        return norm

    def _key_for_path(self, canonical_path: str) -> str:
        return f"bastion:ioc:v1:path:{canonical_path}"

    async def add_path_ioc(
        self,
        path: str,
        source: str,
        reason: str,
        ttl_seconds: int = 86400,
        confidence: float = 1.0,
    ) -> bool:
        """Add a path indicator with an individual key and TTL."""
        if not self.redis:
            return False
        try:
            canonical = self.canonicalize_path(path)
            key = self._key_for_path(canonical)
            payload = {
                "type": "path",
                "path": canonical,
                "source": source,
                "reason": reason,
                "confidence": confidence,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": ttl_seconds,
            }
            await asyncio.wait_for(
                self.redis.set(key, json.dumps(payload), ex=ttl_seconds),
                timeout=self.default_timeout,
            )
            return True
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.error("Failed to add path IOC to Redis: %s", e)
            return False

    async def check_path_ioc(self, path: str) -> Optional[Dict[str, Any]]:
        """Look up active path IOC with exact canonicalized matching."""
        if not self.redis:
            return None
        self.lookup_count += 1
        try:
            canonical = self.canonicalize_path(path)
            key = self._key_for_path(canonical)
            raw = await asyncio.wait_for(
                self.redis.get(key),
                timeout=self.default_timeout,
            )
            if raw:
                self.match_count += 1
                return json.loads(raw)
            return None
        except (asyncio.TimeoutError, aioredis.RedisError, Exception) as e:
            self.error_count += 1
            self.is_degraded = True
            logger.warning("Failed to check path IOC in Redis: %s", e)
            return None

    async def remove_path_ioc(self, path: str) -> bool:
        if not self.redis:
            return False
        try:
            canonical = self.canonicalize_path(path)
            key = self._key_for_path(canonical)
            deleted = await asyncio.wait_for(
                self.redis.delete(key),
                timeout=self.default_timeout,
            )
            return deleted > 0
        except Exception:
            return False
