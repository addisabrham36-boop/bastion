"""Tests for Client-side, Logic, and Application rules (960xxx)."""
from bastion.core.normalizer import normalize_request
from bastion.rules.client_side import (
    PrototypePollutionRule,
    OpenRedirectRule,
    CORSSpoofingRule,
    SessionFixationRule,
    LDAPInjectionRule,
    XPathInjectionRule,
    FileUploadRule,
    GraphQLAbuseRule,
    HPPParameterRule,
)


def _make_request(method="GET", path="/", query_string="", headers=None, body=b""):
    return normalize_request(method, path, query_string=query_string, headers=headers or {}, body=body)


def test_prototype_pollution_blocked():
    req = _make_request(body=b'{"__proto__": {"admin": true}}')
    verdict = PrototypePollutionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960100"


def test_open_redirect_blocked():
    req = _make_request(query_string="redirect=https://evil-phishing.com/login")
    verdict = OpenRedirectRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960110"


def test_cors_null_origin_blocked():
    req = _make_request(headers={"origin": "null"})
    verdict = CORSSpoofingRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960120"


def test_session_fixation_in_query_blocked():
    req = _make_request(query_string="PHPSESSID=1234567890123456")
    verdict = SessionFixationRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960140"


def test_ldap_injection_blocked():
    req = _make_request(query_string="user=*)(&(password=*")
    verdict = LDAPInjectionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960150"


def test_xpath_injection_blocked():
    req = _make_request(query_string="query=' or '1'='1")
    verdict = XPathInjectionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960160"


def test_dangerous_file_upload_blocked():
    body = b'Content-Disposition: form-data; name="file"; filename="webshell.php"\r\n\r\n<?php phpinfo(); ?>'
    req = _make_request(method="POST", body=body)
    verdict = FileUploadRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960170"


def test_graphql_introspection_blocked():
    req = _make_request(body=b'{"query": "{ __schema { types { name } } }"}')
    verdict = GraphQLAbuseRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960180"


def test_hpp_parameter_pollution_blocked():
    req = _make_request(query_string="id=1&id=2&id=3&id=4")
    verdict = HPPParameterRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960200"


def test_clean_client_side_request_allowed():
    req = _make_request(query_string="page=home&lang=en", body=b'{"username": "john_doe"}')
    assert not PrototypePollutionRule().match(req).blocked
    assert not OpenRedirectRule().match(req).blocked
    assert not LDAPInjectionRule().match(req).blocked
    assert not XPathInjectionRule().match(req).blocked
