"""
Immutable RequestContext representing validated request facts,
and EvaluationState collecting detections and score during evaluation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
import uuid


@dataclass(frozen=True)
class RequestContext:
    """Immutable observations about an incoming HTTP request."""
    request_id: str
    received_at: datetime
    started_monotonic: float
    site_id: str
    site_host: str
    client_ip: str
    client_ip_source: str  # "peer" | "trusted_proxy"
    method: str
    raw_path: str
    raw_query: str
    headers: Dict[str, str]
    content_type: str
    declared_content_length: Optional[int]
    body_bytes: bytes
    canonical_path: str
    query_params: Dict[str, List[str]]
    form_params: Dict[str, List[str]]
    json_body: Optional[Any]
    text_body: str
    normalized: Optional[Any] = None

    @classmethod
    def create(
        cls,
        site_id: str,
        site_host: str,
        client_ip: str,
        client_ip_source: str,
        method: str,
        raw_path: str,
        raw_query: str,
        headers: Dict[str, str],
        body_bytes: bytes,
        canonical_path: str,
        query_params: Dict[str, List[str]],
        form_params: Dict[str, List[str]],
        json_body: Optional[Any],
        text_body: str,
        normalized: Optional[Any] = None,
    ) -> "RequestContext":
        cl = headers.get("content-length")
        declared_len = int(cl) if cl and cl.isdigit() else None
        ct = headers.get("content-type", "").split(";")[0].strip().lower()

        return cls(
            request_id=str(uuid.uuid4()),
            received_at=datetime.now(timezone.utc),
            started_monotonic=time.perf_counter(),
            site_id=site_id,
            site_host=site_host,
            client_ip=client_ip,
            client_ip_source=client_ip_source,
            method=method.upper(),
            raw_path=raw_path,
            raw_query=raw_query,
            headers={k.lower(): v for k, v in headers.items()},
            content_type=ct,
            declared_content_length=declared_len,
            body_bytes=body_bytes,
            canonical_path=canonical_path,
            query_params=query_params,
            form_params=form_params,
            json_body=json_body,
            text_body=text_body,
            normalized=normalized,
        )


@dataclass
class Detection:
    """Structured detection emitted by a rule."""
    rule_id: str
    category: str
    severity: str        # "low" | "medium" | "high" | "critical"
    confidence: float    # 0.0 to 1.0
    score: int
    message: str
    location: str
    evidence: str        # Redacted or bounded excerpt
    proposed_action: str = "BLOCK"  # "BLOCK" | "LOG"
    version: int = 1


@dataclass
class EvaluationState:
    """Accumulates detections, score contributions, and notes for one request."""
    detections: List[Detection] = field(default_factory=list)
    score: int = 0
    matched_rule_ids: set = field(default_factory=set)
    notes: List[str] = field(default_factory=list)

    def add_detection(self, detection: Detection):
        # Deduplicate multiple hits of identical rule ID
        if detection.rule_id not in self.matched_rule_ids:
            self.matched_rule_ids.add(detection.rule_id)
            self.detections.append(detection)
            self.score += detection.score
