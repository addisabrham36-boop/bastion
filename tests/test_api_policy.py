"""
Tests for API Method & Content-Type Policy rules (973xxx).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.api_policy import (
    DangerousHTTPMethodRule,
    MethodOverrideHeaderRule,
    DangerousContentTypeRule,
    JSONPrototypePollutionRule,
    GraphQLIntrospectionRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


class TestDangerousHTTPMethodRule:
    rule = DangerousHTTPMethodRule()

    def test_blocks_trace(self):
        r = _req(method="TRACE")
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_connect(self):
        r = _req(method="CONNECT")
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_propfind(self):
        r = _req(method="PROPFIND")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_get(self):
        r = _req(method="GET")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_post(self):
        r = _req(method="POST")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_delete(self):
        r = _req(method="DELETE")
        v = self.rule.match(r)
        assert not v.blocked


class TestMethodOverrideHeaderRule:
    rule = MethodOverrideHeaderRule()

    def test_blocks_x_http_method_override(self):
        r = _req(headers={"x-http-method-override": "DELETE"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_x_method_override(self):
        r = _req(headers={"x-method-override": "PUT"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_no_override_header(self):
        r = _req(headers={"content-type": "application/json"})
        v = self.rule.match(r)
        assert not v.blocked


class TestDangerousContentTypeRule:
    rule = DangerousContentTypeRule()

    def test_blocks_java_serialized_object(self):
        r = _req(headers={"content-type": "application/x-java-serialized-object"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_json_content_type(self):
        r = _req(headers={"content-type": "application/json"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_form_urlencoded(self):
        r = _req(headers={"content-type": "application/x-www-form-urlencoded"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_multipart(self):
        r = _req(headers={"content-type": "multipart/form-data; boundary=xyz"})
        v = self.rule.match(r)
        assert not v.blocked


class TestJSONPrototypePollutionRule:
    rule = JSONPrototypePollutionRule()

    def test_blocks_proto_key(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"__proto__": {"isAdmin": true}}',
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_constructor_key(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"constructor": {"prototype": {"admin": true}}}',
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_java_class_annotation(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"@class": "com.example.Exploit"}',
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_json(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/json"},
            body=b'{"name": "alice", "age": 30}',
        )
        v = self.rule.match(r)
        assert not v.blocked

    def test_ignores_non_json_body(self):
        r = _req(
            method="POST",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b'__proto__=polluted',
        )
        v = self.rule.match(r)
        assert not v.blocked


class TestGraphQLIntrospectionRule:
    rule = GraphQLIntrospectionRule()

    def test_blocks_schema_introspection(self):
        r = _req(
            method="POST",
            body=b'{"query": "{ __schema { types { name } } }"}',
            headers={"content-type": "application/json"},
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_type_introspection(self):
        r = _req(
            method="POST",
            body=b'{"query": "{ __type(name: \\"User\\") { fields { name } } }"}',
            headers={"content-type": "application/json"},
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_graphql_query(self):
        r = _req(
            method="POST",
            body=b'{"query": "{ user(id: 1) { name email } }"}',
            headers={"content-type": "application/json"},
        )
        v = self.rule.match(r)
        assert not v.blocked
