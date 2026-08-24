from bastion.core.normalizer import normalize_request
from bastion.rules.ssrf import SSRFRule


def _match(query_string="", body=b"", headers=None, path="/"):
    request = normalize_request(
        "GET",
        path=path,
        query_string=query_string,
        headers=headers or {},
        body=body,
    )
    return SSRFRule().match(request)


def test_ssrf_localhost_blocked():
    verdict = _match(query_string="webhook=http://127.0.0.1:8080/hook")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_cloud_metadata_blocked():
    verdict = _match(query_string="url=http://169.254.169.254/latest/meta-data/")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_gcp_metadata_blocked():
    verdict = _match(query_string="endpoint=http://metadata.google.internal/computeMetadata/v1/")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_private_class_a_blocked():
    verdict = _match(query_string="target=http://10.0.1.50/admin")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_private_class_c_blocked():
    verdict = _match(query_string="target=http://192.168.1.1/router")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_file_protocol_blocked():
    verdict = _match(query_string="file_url=file:///etc/passwd")
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_clean_public_url_allowed():
    verdict = _match(query_string="webhook=https://api.github.com/webhook&name=test")
    assert not verdict.blocked


def test_ssrf_no_false_positive_on_version_numbers():
    # Software version numbers in query descriptions
    verdict = _match(query_string="info=Installed+Release+10.0.1.5+and+firmware+192.168.1.0")
    assert not verdict.blocked

