"""Tests for HTTP Request Smuggling rules (921100)."""
from bastion.core.normalizer import normalize_request
from bastion.rules.http_smuggling import HTTPSmugglingRule


def _make_request(method="POST", path="/", query_string="", headers=None, body=b""):
    return normalize_request(method, path, query_string=query_string, headers=headers or {}, body=body)


def test_smuggling_cl_te_conflict_blocked():
    req = _make_request(headers={"transfer-encoding": "chunked", "content-length": "42"})
    verdict = HTTPSmugglingRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "921100"


def test_smuggling_xchunked_blocked():
    req = _make_request(headers={"transfer-encoding": "xchunked"})
    verdict = HTTPSmugglingRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "921100"


def test_smuggling_chunked_identity_conflict_blocked():
    req = _make_request(headers={"transfer-encoding": "chunked, identity"})
    verdict = HTTPSmugglingRule().match(req)
    assert verdict.blocked


def test_smuggling_clean_request_allowed():
    req = _make_request(headers={"content-length": "42", "content-type": "application/json"})
    verdict = HTTPSmugglingRule().match(req)
    assert not verdict.blocked
