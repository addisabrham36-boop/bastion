"""
Tests for Security Header Audit rules (976xxx).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.security_headers import (
    CRLFHeaderInjectionRule,
    IPSpoofingForwardedHeaderRule,
    CSPMetaTagInjectionRule,
    RefererHeaderInjectionRule,
    AcceptLanguageInjectionRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


class TestCRLFHeaderInjectionRule:
    rule = CRLFHeaderInjectionRule()

    def test_blocks_cr_in_user_agent(self):
        r = _req(headers={"user-agent": "Mozilla\rX-Injected: evil"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_lf_in_referer(self):
        r = _req(headers={"referer": "https://example.com\nSet-Cookie: evil=1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_headers(self):
        r = _req(headers={
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "referer": "https://example.com/page",
            "accept": "text/html",
        })
        v = self.rule.match(r)
        assert not v.blocked


class TestIPSpoofingForwardedHeaderRule:
    rule = IPSpoofingForwardedHeaderRule()

    def test_blocks_loopback_in_x_forwarded_for(self):
        r = _req(headers={"x-forwarded-for": "127.0.0.1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_private_ip_10_block(self):
        r = _req(headers={"x-forwarded-for": "10.0.0.1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_private_ip_192_168(self):
        r = _req(headers={"x-real-ip": "192.168.1.100"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_172_16_range(self):
        r = _req(headers={"x-forwarded-for": "172.16.0.1"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_public_ip(self):
        r = _req(headers={"x-forwarded-for": "8.8.8.8"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_no_forwarded_headers(self):
        r = _req(headers={"host": "example.com"})
        v = self.rule.match(r)
        assert not v.blocked


class TestCSPMetaTagInjectionRule:
    rule = CSPMetaTagInjectionRule()

    def test_blocks_csp_meta_tag_in_body(self):
        body = b'<meta http-equiv="Content-Security-Policy" content="default-src *">'
        r = _req(method="POST", body=body)
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_csp_meta_mixed_case(self):
        body = b"<META HTTP-EQUIV='Content-Security-Policy' CONTENT='default-src *'>"
        r = _req(method="POST", body=body)
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_html_body(self):
        r = _req(method="POST", body=b"<p>Hello world</p>")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_empty_body(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestRefererHeaderInjectionRule:
    rule = RefererHeaderInjectionRule()

    def test_blocks_script_tag_in_referer(self):
        r = _req(headers={"referer": "https://example.com/<script>alert(1)</script>"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_quote_in_referer(self):
        r = _req(headers={"referer": "https://example.com/\"injected\""})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_referer(self):
        r = _req(headers={"referer": "https://example.com/page?q=hello"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_no_referer(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestAcceptLanguageInjectionRule:
    rule = AcceptLanguageInjectionRule()

    def test_blocks_script_in_accept_language(self):
        r = _req(headers={"accept-language": "en-US,<script>alert(1)</script>"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_crlf_in_accept_language(self):
        r = _req(headers={"accept-language": "en\r\nX-Injected: evil"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_accept_language(self):
        r = _req(headers={"accept-language": "en-US,en;q=0.9,fr;q=0.8"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_no_accept_language(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked
