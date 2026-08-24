from bastion.core.normalizer import normalize_request, repeated_url_decode, strip_null_bytes


def test_repeated_url_decode_single_pass():
    assert repeated_url_decode("%27") == "'"


def test_repeated_url_decode_handles_double_encoding():
    # %2527 -> %27 (pass 1) -> ' (pass 2). A single-pass decoder misses this.
    assert repeated_url_decode("%2527") == "'"


def test_repeated_url_decode_stable_input_unchanged():
    assert repeated_url_decode("hello world") == "hello world"


def test_strip_null_bytes():
    assert strip_null_bytes("file.php\x00.jpg") == "file.php.jpg"


def test_normalize_request_parses_query_params():
    request = normalize_request("GET", "/search", query_string="q=hello&id=42")
    assert request.query_params == {"q": ["hello"], "id": ["42"]}


def test_normalize_request_decodes_query_params():
    request = normalize_request("GET", "/search", query_string="q=1%27%20OR%20%271%27%3D%271")
    assert request.query_params["q"][0] == "1' OR '1'='1"


def test_normalize_request_lowercases_header_keys():
    request = normalize_request("GET", "/", headers={"User-Agent": "curl/8.0"})
    assert request.headers["user-agent"] == "curl/8.0"


def test_normalize_request_decodes_form_body():
    request = normalize_request(
        "POST",
        "/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"user=admin%27--",
    )
    assert "admin'--" in request.body
