"""
Unit tests for Milestone 7: Telemetry schema, UTC ISO timestamps, and Worker batching.
"""

from datetime import datetime
import json
import pytest
from unittest.mock import AsyncMock
from bastion.telemetry.schemas import (
    ClientTelemetry,
    DecisionTelemetry,
    DetectionTelemetry,
    HttpTelemetry,
    SecurityEvent,
    SiteTelemetry,
    TimingTelemetry,
)
from bastion.telemetry.worker import TelemetryWorker


def test_security_event_schema_and_timestamp_parsing():
    event = SecurityEvent(
        request_id="req-12345",
        site=SiteTelemetry(id="demo", host="app.local"),
        client=ClientTelemetry(ip="203.0.113.5", ip_source="peer"),
        http=HttpTelemetry(method="POST", path="/login", status_code=403),
        decision=DecisionTelemetry(
            mode="prevention",
            would_action="BLOCK",
            enforced_action="BLOCK",
            threat_score=80,
            reason_codes=["PAYLOAD_SQLI_001"],
        ),
        detections=[
            DetectionTelemetry(
                rule_id="PAYLOAD_SQLI_001",
                category="payload",
                severity="high",
                confidence=0.85,
                score=40,
            )
        ],
        timing=TimingTelemetry(total_ms=4.2, inspection_ms=1.2),
    )

    data = event.model_dump(by_alias=True)
    # 1. Check timestamp parses strictly as timezone-aware ISO 8601
    ts_str = data["@timestamp"]
    parsed_dt = datetime.fromisoformat(ts_str)
    assert parsed_dt.tzinfo is not None

    # 2. Check no literal '%f' from earlier bug
    assert "%f" not in ts_str


@pytest.mark.asyncio
async def test_telemetry_worker_batching_and_ack():
    mock_redis = AsyncMock()
    mock_opensearch = AsyncMock()

    # Create synthetic stream entry
    event = SecurityEvent(
        request_id="req-test",
        site=SiteTelemetry(id="demo", host="app.local"),
        client=ClientTelemetry(ip="127.0.0.1", ip_source="peer"),
        http=HttpTelemetry(method="GET", path="/", status_code=200),
        decision=DecisionTelemetry(
            mode="detection",
            would_action="ALLOW",
            enforced_action="ALLOW",
            threat_score=0,
        ),
        timing=TimingTelemetry(total_ms=1.0, inspection_ms=0.5),
    )
    raw_payload = json.dumps(event.model_dump(by_alias=True))

    mock_redis.xreadgroup.return_value = [
        ("bastion:events:v1", [("1600000000000-0", {"payload": raw_payload})])
    ]

    worker = TelemetryWorker(mock_redis, mock_opensearch)
    processed = await worker.process_batch(batch_size=10)
    assert processed == 1

    # Verify xack called for message ID
    mock_redis.xack.assert_called_once_with("bastion:events:v1", "bastion_telemetry_workers", "1600000000000-0")
