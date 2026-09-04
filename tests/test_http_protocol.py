"""Tests for HTTP Protocol anomaly rules (920100, 920200, 920300)."""
from bastion.core.normalizer import NormalizedRequest, normalize_request
from bastion.rules.http_protocol import CRLFInjectionRule, HTTPHeaderAnomalyRule, HTTPMethodRule


def _make_request(method="GET", path="/", query_string="", headers=None, body=b""):
    req = normalize_request(method, path, query_string=query_string, headers=headers or {}, body=body)
    return req


# ── 920100 HTTP Method ────────────────────────────────────────────────────────

def test_http_method_trace_blocked():
    req = _make_request(method="TRACE")
    verdict = HTTPMethodRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "920100"


def test_http_method_track_blocked():
    req = _make_request(method="TRACK")
    verdict = HTTPMethodRule().match(req)
    assert verdict.blocked


def test_http_method_debug_blocked():
    req = _make_request(method="DEBUG")
    verdict = HTTPMethodRule().match(req)
    assert verdict.blocked


def test_http_method_get_allowed():
    req = _make_request(method="GET")
    verdict = HTTPMethodRule().match(req)
    assert not verdict.blocked


def test_http_method_post_allowed():
    req = _make_request(method="POST")
    verdict = HTTPMethodRule().match(req)
    assert not verdict.blocked


def test_http_method_delete_allowed():
    req = _make_request(method="DELETE")
    verdict = HTTPMethodRule().match(req)
    assert not verdict.blocked


# ── 920200 Header Anomaly ─────────────────────────────────────────────────────

def test_header_anomaly_oversized_blocked():
    huge_value = "A" * 9000
    req = _make_request(headers={"host": "example.com", "user-agent": huge_value})
    verdict = HTTPHeaderAnomalyRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "920200"


def test_header_anomaly_missing_host_with_other_headers_blocked():
    # Has other headers but no Host — should be blocked
    req = _make_request(headers={"user-agent": "Mozilla/5.0", "content-type": "text/html"})
    verdict = HTTPHeaderAnomalyRule().match(req)
    assert verdict.blocked


def test_header_anomaly_multiple_content_length_blocked():
    req = _make_request(headers={"host": "example.com", "content-length": "10, 20"})
    verdict = HTTPHeaderAnomalyRule().match(req)
    assert verdict.blocked


def test_header_anomaly_clean_request_allowed():
    req = _make_request(headers={"host": "example.com", "content-type": "application/json"})
    verdict = HTTPHeaderAnomalyRule().match(req)
    assert not verdict.blocked


def test_header_anomaly_bare_request_no_headers_allowed():
    # Bare request with no headers — should not be blocked (unit test / internal requests)
    req = _make_request(headers={})
    verdict = HTTPHeaderAnomalyRule().match(req)
    assert not verdict.blocked


# ── 920300 CRLF Injection ─────────────────────────────────────────────────────

def test_crlf_url_encoded_blocked():
    req = _make_request(query_string="redirect=%0d%0aLocation:evil.com")
    verdict = CRLFInjectionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "920300"


def test_crlf_set_cookie_blocked():
    req = _make_request(query_string="msg=%0d%0aSet-Cookie:session=evil")
    verdict = CRLFInjectionRule().match(req)
    assert verdict.blocked


def test_crlf_clean_allowed():
    req = _make_request(query_string="redirect=/dashboard&msg=hello")
    verdict = CRLFInjectionRule().match(req)
    assert not verdict.blocked


def test_crlf_multiline_body_allowed():
    req = _make_request(method="POST", body=b"line1\r\nline2\r\nline3", headers={"content-type": "text/plain"})
    verdict = CRLFInjectionRule().match(req)
    assert not verdict.blocked

