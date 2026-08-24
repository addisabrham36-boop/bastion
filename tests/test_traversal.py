from bastion.core.normalizer import normalize_request
from bastion.rules.traversal import TraversalRule


def _match(query_string="", body=b"", headers=None, path="/"):
    request = normalize_request(
        "GET",
        path=path,
        query_string=query_string,
        headers=headers or {},
        body=body,
    )
    return TraversalRule().match(request)


def test_traversal_dot_dot_slash_blocked():
    verdict = _match(query_string="file=../../etc/passwd")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_in_url_path_blocked():
    verdict = _match(path="/static/../../etc/passwd")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_double_encoded_blocked():
    verdict = _match(query_string="doc=..%252f..%252fetc%252fpasswd")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_proc_self_blocked():
    verdict = _match(query_string="file=/proc/self/environ")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_windows_win_ini_blocked():
    verdict = _match(query_string="file=c:\\windows\\win.ini")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_web_config_blocked():
    verdict = _match(query_string="file=web.config")
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_clean_path_allowed():
    verdict = _match(path="/images/avatar.png", query_string="theme=dark")
    assert not verdict.blocked


def test_traversal_no_false_positive_on_discussion_text():
    verdict = _match(query_string="q=how+to+configure+aspnet+applications+guide")
    assert not verdict.blocked

