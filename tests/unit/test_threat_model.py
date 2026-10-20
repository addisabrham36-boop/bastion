"""
Unit tests for Milestone 10: ThreatModel contract and NullThreatModel.
"""

import pytest
from bastion.core.context import EvaluationState, RequestContext
from bastion.models.base import NullThreatModel


@pytest.mark.asyncio
async def test_null_threat_model_behavior():
    model = NullThreatModel()
    assert model.enabled is False
    assert model.name == "NullThreatModel"

    ctx = RequestContext.create(
        site_id="test",
        site_host="app.local",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path="/",
        raw_query="",
        headers={},
        body_bytes=b"",
        canonical_path="/",
        query_params={},
        form_params={},
        json_body=None,
        text_body="",
    )
    result = await model.predict(ctx, EvaluationState())
    assert result.status == "disabled"
    assert result.score == 0
