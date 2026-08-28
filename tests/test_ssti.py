from bastion.core.normalizer import normalize_request
from bastion.rules.ssti import SSTIRule


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


def _ssti_verdict(query_string="", body=b"", path="/"):
    request = _make_request(query_string=query_string, body=body, path=path)
    return SSTIRule().match(request)


# ---------------------------------------------------------------------------
# SSTIRule (952100)
# ---------------------------------------------------------------------------


def test_ssti_jinja2_arithmetic_blocked():
    verdict = _ssti_verdict(query_string="name={{7*7}}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_el_arithmetic_blocked():
    # FreeMarker / Java EL style ${7*7}
    verdict = _ssti_verdict(query_string="q=${7*7}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_velocity_set_blocked():
    verdict = _ssti_verdict(query_string="tmpl=#set($x=7*7)")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_velocity_foreach_blocked():
    verdict = _ssti_verdict(body=b"#foreach($i in [1..3])$i#end")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_freemarker_assign_blocked():
    verdict = _ssti_verdict(body=b"<#assign x = 7*7>${x}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_jinja2_config_access_blocked():
    verdict = _ssti_verdict(query_string="tpl={{config}}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_handlebars_each_blocked():
    verdict = _ssti_verdict(body=b"{{#each items}}{{this}}{{/each}}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_smarty_php_tag_blocked():
    verdict = _ssti_verdict(body=b"{php}echo 'hello';{/php}")
    assert verdict.blocked
    assert verdict.rule_id == "952100"


def test_ssti_clean_search_allowed():
    verdict = _ssti_verdict(query_string="q=hello+world&page=1")
    assert not verdict.blocked


def test_ssti_clean_template_name_allowed():
    verdict = _ssti_verdict(query_string="template=default&lang=en")
    assert not verdict.blocked
