"""
Request normalization — runs before every rule in engine.py.
Handles repeated URL-decoding, null-byte stripping, and unicode normalization.

Content-Type-aware body decoding
---------------------------------
* application/x-www-form-urlencoded and unknown types:
    Full repeated URL-decode + null-byte strip (original WAF path).
* multipart/*, application/octet-stream, image/*, audio/*, video/*:
    UTF-8 decode only (replacement mode) + null-byte strip on the string.
    URL-decoding is intentionally skipped to keep MIME boundaries intact
    and to preserve encoded sequences in filenames for rule inspection.
    The original bytes are always available via NormalizedRequest.raw_body.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import unquote_plus

SCANNED_HEADERS: Tuple[str, ...] = ("user-agent", "referer", "cookie", "x-forwarded-for", "origin")

# Content-Type prefixes whose bodies must NOT be URL-decoded.
_SKIP_URL_DECODE_PREFIXES: Tuple[str, ...] = (
    "multipart/",
    "application/octet-stream",
    "image/",
    "audio/",
    "video/",
)


@dataclass
class NormalizedRequest:
    """Canonical form of an HTTP request, ready for rule matching."""

    method: str
    path: str
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_body: bytes = field(default_factory=bytes)
    client_ip: str = ""

    def iter_values(self) -> Iterator[Tuple[str, str]]:
        """Yield (field_label, value) for every user-controlled string."""
        if self.path:
            yield "path", self.path
        for key, values in self.query_params.items():
            if key:
                yield f"query_key:{key}", key
            for value in values:
                yield f"query:{key}", value
        if self.body:
            yield "body", self.body
        for header_name in SCANNED_HEADERS:
            if header_name in self.headers:
                yield f"header:{header_name}", self.headers[header_name]


def repeated_url_decode(value: str, max_iterations: int = 5) -> str:
    """Decode %-encoding repeatedly until it stabilizes."""
    decoded = value
    for _ in range(max_iterations):
        next_pass = unquote_plus(decoded)
        if next_pass == decoded:
            break
        decoded = next_pass
    return decoded


def strip_null_bytes(value: str) -> str:
    """Remove null bytes used in evasion."""
    return value.replace("\x00", "")


def _parse_query_string(query_string: str) -> Dict[str, List[str]]:
    params: Dict[str, List[str]] = {}
    if not query_string:
        return params
    for pair in query_string.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        key = strip_null_bytes(repeated_url_decode(key))
        value = strip_null_bytes(repeated_url_decode(value))
        params.setdefault(key, []).append(value)
    return params


def _should_skip_url_decode(content_type: str) -> bool:
    """Return True if this content type's body must NOT be URL-decoded."""
    ct = content_type.lower().strip()
    return any(ct.startswith(prefix) for prefix in _SKIP_URL_DECODE_PREFIXES)


def _decode_body(body: Union[bytes, str], content_type: str = "") -> str:
    """
    Convert raw body to an inspectable string for rule matching.

    For URL-encoded and unknown content types: full repeated URL-decode +
    null-byte strip.

    For multipart / binary / media: UTF-8 decode (replacement) + null-byte
    strip only.  URL-decoding is intentionally skipped.
    """
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return ""
    else:
        text = body

    if _should_skip_url_decode(content_type):
        return strip_null_bytes(text)

    return strip_null_bytes(repeated_url_decode(text))


def normalize_request(
    method: str,
    path: str,
    query_string: str = "",
    headers: Optional[Dict[str, str]] = None,
    body: Union[bytes, str] = b"",
    client_ip: str = "",
) -> NormalizedRequest:
    normalized_headers = {k.lower(): v for k, v in (headers or {}).items()}
    content_type = normalized_headers.get("content-type", "")

    # Preserve the original body bytes before any transformation.
    raw_body: bytes = body if isinstance(body, bytes) else body.encode("utf-8", errors="replace")

    return NormalizedRequest(
        method=method.upper(),
        path=strip_null_bytes(repeated_url_decode(path)),
        query_params=_parse_query_string(query_string),
        headers=normalized_headers,
        body=_decode_body(body, content_type),
        raw_body=raw_body,
        client_ip=client_ip,
    )
