"""
Tests for Host Header Manipulation rules (970xxx).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.host_header import (
    HostHeaderInjectionRule,
    HostHeaderAtSignRule,
    CachePoisonHostOverrideRule,
    PasswordResetPoisoningRule,
    InternalHostRoutingRule,
    AbsoluteURIRequestTargetRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


# ── HostHeaderInjectionRule ───────────────────────────────────────────────────

class TestHostHeaderInjectionRule:
    rule = HostHeaderInjectionRule()

    def test_blocks_crlf_in_host(self):
        r = _req(headers={"host": "example.com\r\nX-Injected: evil"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_tab_in_host(self):
        r = _req(headers={"host": "example.com\tX-Injected: evil"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_host(self):
        r = _req(headers={"host": "example.com"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_host_with_port(self):
        r = _req(headers={"host": "example.com:8080"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_missing_host(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


# ── HostHeaderAtSignRule ──────────────────────────────────────────────────────

class TestHostHeaderAtSignRule:
    rule = HostHeaderAtSignRule()

    def test_blocks_at_sign_in_host(self):
        r = _req(headers={"host": "attacker@evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_host(self):
        r = _req(headers={"host": "example.com"})
        v = self.rule.match(r)
        assert not v.blocked


# ── CachePoisonHostOverrideRule ───────────────────────────────────────────────

class TestCachePoisonHostOverrideRule:
    rule = CachePoisonHostOverrideRule()

    def test_blocks_x_forwarded_host(self):
        r = _req(headers={"x-forwarded-host": "evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_x_original_host(self):
        r = _req(headers={"x-original-host": "evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_x_host(self):
        r = _req(headers={"x-host": "evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_no_override_headers(self):
        r = _req(headers={"host": "example.com", "content-type": "application/json"})
        v = self.rule.match(r)
        assert not v.blocked


# ── PasswordResetPoisoningRule ────────────────────────────────────────────────

class TestPasswordResetPoisoningRule:
    rule = PasswordResetPoisoningRule()

    def test_blocks_reset_path_with_x_forwarded_host(self):
        r = _req(path="/api/password/reset", headers={"x-forwarded-host": "evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_forgot_path_with_x_host(self):
        r = _req(path="/forgot-password", headers={"x-host": "evil.com"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_reset_without_override_header(self):
        r = _req(path="/api/password/reset", headers={"host": "example.com"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_login_with_forwarded_host(self):
        # Not a reset path — should not fire
        r = _req(path="/login", headers={"x-forwarded-host": "evil.com"})
        v = self.rule.match(r)
        # CachePoisonHostOverrideRule would catch this, but THIS rule should not
        assert v.rule_id == "970115" and not v.blocked


# ── InternalHostRoutingRule ───────────────────────────────────────────────────

class TestInternalHostRoutingRule:
    rule = InternalHostRoutingRule()

    def test_blocks_loopback_in_x_forwarded_host(self):
        r = _req(headers={"x-forwarded-host": "127.0.0.1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_private_ip_in_host(self):
        r = _req(headers={"host": "192.168.1.1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_public_ip_in_host(self):
        r = _req(headers={"host": "8.8.8.8"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_normal_domain(self):
        r = _req(headers={"host": "example.com"})
        v = self.rule.match(r)
        assert not v.blocked


# ── AbsoluteURIRequestTargetRule ──────────────────────────────────────────────

class TestAbsoluteURIRequestTargetRule:
    rule = AbsoluteURIRequestTargetRule()

    def test_blocks_absolute_http_uri(self):
        r = _req(path="http://internal.corp/secret")
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_absolute_https_uri(self):
        r = _req(path="https://internal.corp/admin")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_relative_path(self):
        r = _req(path="/api/v1/users")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_root_path(self):
        r = _req(path="/")
        v = self.rule.match(r)
        assert not v.blocked
