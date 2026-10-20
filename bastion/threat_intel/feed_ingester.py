"""
Threat feed ingestion module for Bastion-TIP.
Validates indicator records and ingests them into RedisIOCRepository with
fault-tolerant batch processing.
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional
from ..storage.ioc_repository import RedisIOCRepository

logger = logging.getLogger("bastion.threat_intel.ingest")

_VALID_TYPES = {"ip", "domain", "path"}
_MAX_TTL = 30 * 86400  # 30 days in seconds
_MIN_TTL = 1           # 1 second


@dataclass
class IngestResult:
    """Summary of batch ingestion execution."""
    ingested: int = 0
    rejected: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.ingested + self.rejected


class ThreatFeedIngester:
    """
    Validates and ingests threat intelligence feed records into the Redis IOC repository.
    Guarantees that individual malformed records do not corrupt or abort the batch.
    """

    def __init__(self, repo: RedisIOCRepository):
        self.repo = repo

    def validate_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate an indicator record dictionary.
        Returns a cleaned, normalized record or raises ValueError on validation error.
        """
        if not isinstance(record, dict):
            raise ValueError(f"Record must be a dictionary, got {type(record).__name__}")

        # 1. Type validation
        raw_type = str(record.get("type", "")).strip().lower()
        if raw_type not in _VALID_TYPES:
            raise ValueError(f"Invalid indicator type '{raw_type}'. Supported: {sorted(_VALID_TYPES)}")

        # 2. Value validation
        raw_val = record.get("value") or record.get("indicator") or record.get(raw_type)
        if not raw_val or not isinstance(raw_val, str) or not raw_val.strip():
            raise ValueError(f"Indicator value cannot be empty for type '{raw_type}'")
        raw_val = raw_val.strip()

        # 3. Canonicalization check per type
        if raw_type == "ip":
            canonical_val = self.repo.canonicalize_ip(raw_val)
        elif raw_type == "domain":
            canonical_val = self.repo.canonicalize_domain(raw_val)
        elif raw_type == "path":
            canonical_val = self.repo.canonicalize_path(raw_val)
        else:
            raise ValueError(f"Unsupported type: {raw_type}")

        # 4. Source & Reason
        source = str(record.get("source", "manual")).strip() or "manual"
        reason = str(record.get("reason", "Threat intelligence indicator")).strip() or "Threat intelligence indicator"

        # 5. Confidence validation (0.0 to 1.0)
        try:
            confidence = float(record.get("confidence", 1.0))
            if not (0.0 <= confidence <= 1.0):
                raise ValueError()
        except Exception:
            raise ValueError(f"Confidence must be a float between 0.0 and 1.0, got '{record.get('confidence')}'")

        # 6. TTL validation (1 second to 30 days)
        try:
            ttl_seconds = int(record.get("ttl_seconds", 86400))
            if not (_MIN_TTL <= ttl_seconds <= _MAX_TTL):
                raise ValueError()
        except Exception:
            raise ValueError(
                f"TTL seconds must be an integer between {_MIN_TTL} and {_MAX_TTL}, got '{record.get('ttl_seconds')}'"
            )

        # 7. Domain options
        allow_subdomains = bool(record.get("allow_subdomains", False)) if raw_type == "domain" else False

        return {
            "type": raw_type,
            "value": canonical_val,
            "source": source,
            "reason": reason,
            "confidence": confidence,
            "ttl_seconds": ttl_seconds,
            "allow_subdomains": allow_subdomains,
        }

    async def ingest_record(self, record: Dict[str, Any]) -> bool:
        """Validate and ingest a single indicator record."""
        cleaned = self.validate_record(record)
        t = cleaned["type"]
        val = cleaned["value"]
        src = cleaned["source"]
        rsn = cleaned["reason"]
        conf = cleaned["confidence"]
        ttl = cleaned["ttl_seconds"]

        if t == "ip":
            return await self.repo.add_ip_ioc(ip=val, source=src, reason=rsn, ttl_seconds=ttl, confidence=conf)
        elif t == "domain":
            return await self.repo.add_domain_ioc(
                domain=val, source=src, reason=rsn, ttl_seconds=ttl, confidence=conf,
                allow_subdomains=cleaned["allow_subdomains"],
            )
        elif t == "path":
            return await self.repo.add_path_ioc(path=val, source=src, reason=rsn, ttl_seconds=ttl, confidence=conf)
        return False

    async def ingest_batch(self, records: List[Dict[str, Any]]) -> IngestResult:
        """
        Batch ingest indicator records.
        Processes all valid items; records and skips any invalid records.
        """
        result = IngestResult()
        if not isinstance(records, (list, tuple)):
            result.rejected = 1
            result.errors.append("Batch must be a list of records")
            return result

        for idx, rec in enumerate(records):
            try:
                success = await self.ingest_record(rec)
                if success:
                    result.ingested += 1
                else:
                    result.rejected += 1
                    result.errors.append(f"Record #{idx}: Repository storage failed")
            except Exception as e:
                result.rejected += 1
                result.errors.append(f"Record #{idx}: {str(e)}")

        return result
