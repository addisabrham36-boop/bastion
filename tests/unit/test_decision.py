"""
Unit tests for Milestone 4: RuleRegistry, RuleEngine, and DecisionEngine.
"""

import pytest
from bastion.core.context import Detection, EvaluationState, RequestContext
from bastion.core.decision import DecisionEngine
from bastion.core.enums import DecisionAction, Mode, RuleCategory, Severity
from bastion.proxy.router import SiteConfig
from bastion.rules.base import BaseRule
from bastion.rules.registry import RuleEngine, RuleRegistry


class DummySQLiRule(BaseRule):
    id = "PAYLOAD_SQLI_001"
    name = "Dummy SQLi"
    category = RuleCategory.PAYLOAD
    severity = Severity.HIGH
    confidence = 0.9
    score = 50
    enabled = True

    def evaluate(self, context: RequestContext, state: EvaluationState):
        if "' or 1=1" in context.raw_query.lower():
            return Detection(
                rule_id=self.id,
                category=self.category.value,
                severity=self.severity.value,
                confidence=self.confidence,
                score=self.score,
                message="SQLi detected",
                location="query",
                evidence="' or 1=1",
            )
        return None


def test_rule_registry_and_engine():
    registry = RuleRegistry()
    rule = DummySQLiRule()
    registry.register(rule)

    # Duplicate registration check
    with pytest.raises(ValueError):
        registry.register(rule)

    engine = RuleEngine(registry)

    ctx_clean = RequestContext.create(
        site_id="demo",
        site_host="app.local",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path="/search",
        raw_query="q=shoes",
        headers={},
        body_bytes=b"",
        canonical_path="/search",
        query_params={"q": ["shoes"]},
        form_params={},
        json_body=None,
        text_body="",
    )
    state_clean = engine.evaluate(ctx_clean)
    assert len(state_clean.detections) == 0
    assert state_clean.score == 0

    ctx_attack = RequestContext.create(
        site_id="demo",
        site_host="app.local",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path="/search",
        raw_query="q=' or 1=1",
        headers={},
        body_bytes=b"",
        canonical_path="/search",
        query_params={"q": ["' or 1=1"]},
        form_params={},
        json_body=None,
        text_body="",
    )
    state_attack = engine.evaluate(ctx_attack)
    assert len(state_attack.detections) == 1
    assert state_attack.score == 50
    assert "PAYLOAD_SQLI_001" in state_attack.matched_rule_ids


def test_decision_engine_detection_vs_prevention():
    rule = DummySQLiRule()
    state = EvaluationState()
    detection = Detection(
        rule_id=rule.id,
        category=rule.category.value,
        severity=rule.severity.value,
        confidence=rule.confidence,
        score=50,
        message="SQLi detected",
        location="query",
        evidence="test",
    )
    state.add_detection(detection)

    ctx = RequestContext.create(
        site_id="demo",
        site_host="app.local",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path="/search",
        raw_query="q=' or 1=1",
        headers={},
        body_bytes=b"",
        canonical_path="/search",
        query_params={},
        form_params={},
        json_body=None,
        text_body="",
    )

    # 1. Detection Mode: would_action=BLOCK, action=ALLOW
    site_detection = SiteConfig(
        id="demo",
        hostnames=["app.local"],
        upstream_origin="http://127.0.0.1:5000",
        mode="detection",
    )
    decision = DecisionEngine.decide(ctx, state, site_detection)
    assert decision.would_action == DecisionAction.BLOCK
    assert decision.action == DecisionAction.ALLOW
    assert decision.threat_score == 50

    # 2. Prevention Mode: would_action=BLOCK, action=BLOCK
    site_prevention = SiteConfig(
        id="demo",
        hostnames=["app.local"],
        upstream_origin="http://127.0.0.1:5000",
        mode="prevention",
    )
    decision = DecisionEngine.decide(ctx, state, site_prevention)
    assert decision.would_action == DecisionAction.BLOCK
    assert decision.action == DecisionAction.BLOCK
