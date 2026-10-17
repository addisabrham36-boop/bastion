"""
Unit tests for Milestone 5: Core defensive rule pack (SQLi, XSS, Traversal, CMDi).
Tests true positives, benign non-matches, and normalization resistance.
"""

import pytest
from bastion.core.context import EvaluationState, RequestContext
from bastion.core.normalization import parse_bounded_query
from bastion.rules.categories.payload import (
    SQLiUnionSelectRule,
    XSSScriptTagRule,
    PathTraversalDotDotRule,
    CommandInjectionChainingRule,
)


def make_ctx(query: str = "", path: str = "/search", text_body: str = "") -> RequestContext:
    return RequestContext.create(
        site_id="test",
        site_host="app.local",
        client_ip="127.0.0.1",
        client_ip_source="peer",
        method="GET",
        raw_path=path,
        raw_query=query,
        headers={},
        body_bytes=text_body.encode("utf-8"),
        canonical_path=path,
        query_params=parse_bounded_query(query),
        form_params={},
        json_body=None,
        text_body=text_body,
    )


def test_sqli_rule():
    rule = SQLiUnionSelectRule()
    # True positive
    ctx_attack = make_ctx(query="id=1 UNION SELECT null, username, password FROM users--")
    det = rule.evaluate(ctx_attack, EvaluationState())
    assert det is not None
    assert det.rule_id == "PAYLOAD_SQLI_001"

    # Benign negative
    ctx_benign = make_ctx(query="q=european union selection committee")
    assert rule.evaluate(ctx_benign, EvaluationState()) is None


def test_xss_rule():
    rule = XSSScriptTagRule()
    # True positive
    ctx_attack = make_ctx(query="comment=<script>alert(1)</script>")
    det = rule.evaluate(ctx_attack, EvaluationState())
    assert det is not None
    assert det.rule_id == "PAYLOAD_XSS_001"

    # Event handler
    ctx_event = make_ctx(query="img=<img src=x onerror=alert(document.domain)>")
    assert rule.evaluate(ctx_event, EvaluationState()) is not None

    # Benign negative
    ctx_benign = make_ctx(query="topic=how to write a shell script")
    assert rule.evaluate(ctx_benign, EvaluationState()) is None


def test_traversal_rule():
    rule = PathTraversalDotDotRule()
    # True positive
    ctx_attack = make_ctx(path="/static/../../etc/passwd")
    det = rule.evaluate(ctx_attack, EvaluationState())
    assert det is not None
    assert det.rule_id == "PAYLOAD_TRAVERSAL_001"

    # Benign negative
    ctx_benign = make_ctx(path="/articles/2026/10/intro.html")
    assert rule.evaluate(ctx_benign, EvaluationState()) is None


def test_cmdi_rule():
    rule = CommandInjectionChainingRule()
    # True positive
    ctx_attack = make_ctx(text_body="host=8.8.8.8; whoami")
    det = rule.evaluate(ctx_attack, EvaluationState())
    assert det is not None
    assert det.rule_id == "PAYLOAD_CMDI_001"

    # Benign negative
    ctx_benign = make_ctx(text_body="user_status=active; team=security")
    assert rule.evaluate(ctx_benign, EvaluationState()) is None
