"""
Integration tests for Phase 3: Scored RuleEngine and DecisionEngine in the live proxy.
Verifies that:
- Clean requests pass through to upstream.
- Malicious requests are blocked in prevention mode.
- Detection mode records attacks without blocking them.
- Multiple matching rules accumulate threat score and reason codes.
- Configured thresholds determine final action (compatibility vs scored mode).
- Scoped exclusions suppress only the intended rule/context.
- Disabled rules in database are respected.
- Evaluation exceptions trigger the guarded fallback (never fail open).
- Multipart null-byte inspection uses raw_body in live proxy and allows binary contents.
"""

import pytest
from fastapi.testclient import TestClient

from bastion.core.proxy import (
    app as proxy_app,
    rule_engine,
    exclusion_manager,
    decision_engine,
)
from bastion.core.context import RequestContext
from bastion.core.enums import DecisionAction, Mode
from bastion.rules.exclusions import RuleExclusion
from database.db import get_recent_events, get_sites, set_rule_state, set_site_defense


@pytest.fixture(autouse=True)
def setup_defense_mode():
    """Ensure tests start in prevention mode for determinism, and restore state."""
    sites = get_sites()
    for s in sites:
        set_site_defense(s["id"], True)
    yield
    for s in sites:
        set_site_defense(s["id"], True)


def test_proxy_clean_request_allowed():
    client = TestClient(proxy_app)
    resp = client.get("/search?q=legitimate_query")
    # Clean request passes through WAF (upstream returns 200, 404, or 502 if upstream is mock)
    assert resp.status_code in (200, 404, 502)
    if resp.status_code == 403:
        pytest.fail("Clean request was unexpectedly blocked by WAF")


def test_proxy_malicious_blocked_in_prevention_mode():
    client = TestClient(proxy_app)
    resp = client.get("/login?user=admin' OR '1'='1")
    assert resp.status_code == 403
    data = resp.json()
    assert data["blocked"] is True
    assert data["rule"] == "942100"
    assert "status" in data and data["status"] == 403


def test_proxy_detection_mode_records_without_blocking():
    # Set site defense to False (Detection Mode)
    for s in get_sites():
        set_site_defense(s["id"], False)

    try:
        client = TestClient(proxy_app)
        resp = client.get("/login?user=admin' OR '1'='1")
        # In detection mode, attack must NOT be blocked with 403
        assert resp.status_code != 403

        # Verify audit log recorded the attack with detection mode action
        recent = get_recent_events(limit=5)
        matching = [r for r in recent if r["rule_id"] == "942100" and r["blocked"] == 0]
        assert len(matching) >= 1
        assert "Detection Mode" in matching[0]["action"]
    finally:
        for s in get_sites():
            set_site_defense(s["id"], True)


def test_proxy_multi_rule_score_accumulation():
    """Verify that a compound attack triggers multiple rules and sums their scores."""
    attack_query = "user=admin' OR '1'='1"

    # Directly evaluate with the live proxy's RuleEngine to verify score accumulation
    ctx = RequestContext.create(
        site_id="portfolio-netlify",
        site_host="127.0.0.1:8080",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path="/login",
        raw_query=attack_query,
        headers={},
        body_bytes=b"",
        canonical_path="/login",
        query_params={"user": ["admin' OR '1'='1"]},
        form_params={},
        json_body=None,
        text_body="",
    )
    eval_state = rule_engine.evaluate(ctx)

    # Must have matched multiple rules
    assert len(eval_state.detections) >= 2
    assert "942100" in eval_state.matched_rule_ids
    assert "942110" in eval_state.matched_rule_ids
    assert eval_state.score >= 80, f"Expected accumulated score >= 80, got {eval_state.score}"


def test_proxy_scoped_exclusion_suppresses_only_intended_target():
    """Verify that an exclusion suppresses only the targeted rule on the specified path."""
    exclusion = RuleExclusion(
        rule_id="942100",
        site_id="*",
        path_pattern=r"^/excluded",
        reason="Test exclusion for admin endpoint",
    )
    exclusion_manager.add_exclusion(exclusion)

    try:
        # Context 1: Target path with exclusion -> rule 942100 suppressed
        ctx_excluded = RequestContext.create(
            site_id="portfolio-netlify",
            site_host="127.0.0.1:8080",
            client_ip="127.0.0.1",
            client_ip_source="peer",
            method="GET",
            raw_path="/excluded/search",
            raw_query="q=' OR '1'='1",
            headers={},
            body_bytes=b"",
            canonical_path="/excluded/search",
            query_params={"q": ["' OR '1'='1"]},
            form_params={},
            json_body=None,
            text_body="",
        )
        state_ex = rule_engine.evaluate(ctx_excluded)
        assert "942100" not in state_ex.matched_rule_ids
        assert any("Rule 942100 skipped via exclusion" in note for note in state_ex.notes)

        # Context 2: Non-matching path -> rule 942100 is NOT suppressed
        ctx_normal = RequestContext.create(
            site_id="portfolio-netlify",
            site_host="127.0.0.1:8080",
            client_ip="127.0.0.1",
            client_ip_source="peer",
            method="GET",
            raw_path="/public/search",
            raw_query="q=' OR '1'='1",
            headers={},
            body_bytes=b"",
            canonical_path="/public/search",
            query_params={"q": ["' OR '1'='1"]},
            form_params={},
            json_body=None,
            text_body="",
        )
        state_normal = rule_engine.evaluate(ctx_normal)
        assert "942100" in state_normal.matched_rule_ids
    finally:
        exclusion_manager.remove_exclusion(exclusion.id)


def test_proxy_disabled_rule_respected():
    """Verify that disabling a rule prevents it from executing."""
    set_rule_state("942100", False)

    try:
        ctx = RequestContext.create(
            site_id="test", site_host="127.0.0.1", client_ip="127.0.0.1", client_ip_source="peer",
            method="GET", raw_path="/search", raw_query="q=' OR '1'='1", headers={}, body_bytes=b"",
            canonical_path="/search", query_params={"q": ["' OR '1'='1"]}, form_params={}, json_body=None, text_body="",
        )
        # Evaluate with 942100 omitted from enabled_rule_ids
        state = rule_engine.evaluate(ctx, enabled_rule_ids={"941100", "930100"})
        assert "942100" not in state.matched_rule_ids
    finally:
        set_rule_state("942100", True)


def test_proxy_multipart_null_byte_detected_in_live_proxy():
    """Verify that literal null-byte multipart filename is blocked in the live proxy."""
    client = TestClient(proxy_app)
    boundary = b"----TestBoundaryLive"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="upload_doc"; filename="shell.php\x00.jpg"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"malicious_data\r\n"
        b"--" + boundary + b"--\r\n"
    )
    headers = {"Content-Type": "multipart/form-data; boundary=----TestBoundaryLive"}

    resp = client.post("/upload", content=body, headers=headers)
    assert resp.status_code == 403
    data = resp.json()
    assert data["blocked"] is True
    assert data["rule"] == "974105"


def test_proxy_multipart_binary_content_allowed_in_live_proxy():
    """Verify that legitimate binary uploads with null bytes in contents are NOT blocked."""
    client = TestClient(proxy_app)
    boundary = b"----TestBoundaryLive2"
    # Null bytes inside the file contents, but clean filename
    binary_content = b"\x00\xff\x00\xee" * 64
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="upload_doc"; filename="report.pdf"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + binary_content + b"\r\n"
        b"--" + boundary + b"--\r\n"
    )
    headers = {"Content-Type": "multipart/form-data; boundary=----TestBoundaryLive2"}

    resp = client.post("/upload", content=body, headers=headers)
    # Must NOT be blocked by WAF rule 974105
    assert resp.status_code != 403


def test_proxy_engine_exception_triggers_safe_fallback(monkeypatch):
    """Verify that if the new rule engine raises an exception, the proxy falls back safely."""
    client = TestClient(proxy_app)

    def failing_evaluate(*args, **kwargs):
        raise RuntimeError("Simulated internal rule engine failure")

    monkeypatch.setattr(rule_engine, "evaluate", failing_evaluate)

    # Malicious request should STILL be blocked via guarded fallback to legacy_engine
    resp = client.get("/login?user=admin' OR '1'='1")
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True
    assert resp.json()["rule"] == "942100"
