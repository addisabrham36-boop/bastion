"""
Tests for Resource Exhaustion / DoS rules (975xxx).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.resource_exhaustion import (
    OversizedRequestBodyRule,
    OversizedQueryStringRule,
    TooManyQueryParametersRule,
    JSONBombRule,
    XMLEntityBombRule,
    RangeHeaderBombRule,
    OversizedCookieRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


class TestOversizedRequestBodyRule:
    rule = OversizedRequestBodyRule()

    def test_blocks_oversized_body(self):
        # 11 MB body
        r = _req(method="POST", body=b"A" * (11 * 1024 * 1024))
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_body(self):
        r = _req(method="POST", body=b'{"name": "alice"}')
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_empty_body(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestOversizedQueryStringRule:
    rule = OversizedQueryStringRule()

    def test_blocks_oversized_query(self):
        long_qs = "q=" + "A" * 9000
        r = _req(query=long_qs)
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_query(self):
        r = _req(query="search=hello&page=1")
        v = self.rule.match(r)
        assert not v.blocked


class TestTooManyQueryParametersRule:
    rule = TooManyQueryParametersRule()

    def test_blocks_too_many_params(self):
        qs = "&".join(f"p{i}=v{i}" for i in range(150))
        r = _req(query=qs)
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_param_count(self):
        qs = "&".join(f"p{i}=v{i}" for i in range(10))
        r = _req(query=qs)
        v = self.rule.match(r)
        assert not v.blocked


class TestJSONBombRule:
    rule = JSONBombRule()

    def test_blocks_deeply_nested_json(self):
        # 60 levels of nesting
        nested = "{" * 60 + '"x": 1' + "}" * 60
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=nested.encode(),
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_json(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"user": {"name": "alice", "roles": ["admin"]}}',
        )
        v = self.rule.match(r)
        assert not v.blocked

    def test_ignores_non_json_body(self):
        nested = "{" * 60 + '"x": 1' + "}" * 60
        r = _req(
            method="POST",
            headers={"content-type": "text/plain"},
            body=nested.encode(),
        )
        v = self.rule.match(r)
        assert not v.blocked


class TestXMLEntityBombRule:
    rule = XMLEntityBombRule()

    def test_blocks_entity_declaration(self):
        xml_bomb = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE bomb [<!ENTITY lol "lol">]>'
            b"<root>&lol;</root>"
        )
        r = _req(
            method="POST",
            headers={"content-type": "text/xml"},
            body=xml_bomb,
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_xml(self):
        r = _req(
            method="POST",
            headers={"content-type": "text/xml"},
            body=b"<?xml version='1.0'?><root><item>value</item></root>",
        )
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_normal_json(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"key": "value"}',
        )
        v = self.rule.match(r)
        assert not v.blocked


class TestRangeHeaderBombRule:
    rule = RangeHeaderBombRule()

    def test_blocks_many_ranges(self):
        ranges = "bytes=" + ",".join(f"{i}-{i+1}" for i in range(0, 50, 2))
        r = _req(headers={"range": ranges})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_single_range(self):
        r = _req(headers={"range": "bytes=0-1023"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_no_range_header(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestOversizedCookieRule:
    rule = OversizedCookieRule()

    def test_blocks_oversized_cookie(self):
        r = _req(headers={"cookie": "session=" + "x" * 5000})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_cookie(self):
        r = _req(headers={"cookie": "session=abc123; user=alice"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_no_cookie(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked
