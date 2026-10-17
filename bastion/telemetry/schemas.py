"""
Versioned SecurityEvent telemetry schema.
Generates timezone-aware ISO-8601 UTC timestamps, fixing the earlier strftime %f formatting bug.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class SiteTelemetry(BaseModel):
    id: str
    host: str


class ClientTelemetry(BaseModel):
    ip: str
    ip_source: str
    user_agent: Optional[str] = None


class HttpTelemetry(BaseModel):
    method: str
    path: str
    status_code: int
    upstream_status_code: Optional[int] = None


class DecisionTelemetry(BaseModel):
    mode: str
    would_action: str
    enforced_action: str
    threat_score: int
    reason_codes: List[str] = Field(default_factory=list)


class DetectionTelemetry(BaseModel):
    rule_id: str
    category: str
    severity: str
    confidence: float
    score: int


class TimingTelemetry(BaseModel):
    total_ms: float
    inspection_ms: float


class ModelTelemetry(BaseModel):
    enabled: bool = False
    name: Optional[str] = None
    version: Optional[str] = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: int = 1
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        alias="@timestamp",
    )
    request_id: str
    site: SiteTelemetry
    client: ClientTelemetry
    http: HttpTelemetry
    decision: DecisionTelemetry
    detections: List[DetectionTelemetry] = Field(default_factory=list)
    timing: TimingTelemetry
    model: ModelTelemetry = Field(default_factory=ModelTelemetry)
