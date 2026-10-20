"""
Multipart / File-Upload Integrity Rules (OWASP CRS 974xxx).
Detects filename traversal, dangerous extensions, polyglot payloads, and oversized uploads.

Design note on body inspection
--------------------------------
Rules that inspect filenames inside multipart Content-Disposition headers have
two views of the body available:

  request.body    — normalised string: null bytes stripped from the UTF-8 text.
                    Good for text-based pattern matching (extensions, traversal).
  request.raw_body — original bytes, byte-for-byte unchanged.
                    Required for null-byte detection because the normaliser
                    strips \\x00 from the string representation.

FileUploadNullByteRule uses raw_body so literal \\x00 bytes in filenames are
detected regardless of what the normaliser did to the string copy.

The remaining rules (extension, traversal, double-ext, oversized) operate on
the normalised body string, which is fine: those patterns survive normalization
and do not depend on null bytes being present.
"""

import re
from .base import Rule, Verdict

# Scan at most the first 64 KB of multipart headers for rules that read body string.
_SCAN_LIMIT_STR = 65536
# Scan at most the first 64 KB of raw bytes for the null-byte rule.
_SCAN_LIMIT_RAW = 65536


def _upload_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# ── Patterns for string-based body inspection ─────────────────────────────────

# Dangerous file extensions (server-executable or archive-bomb)
_DANGEROUS_EXT = re.compile(
    r"\.(?:php\d?|phtml|phar|asp|aspx|jsp|jspx|cfm|cfc|pl|py|rb|sh|bash|"
    r"cmd|bat|ps1|vbs|vbe|js|jse|wsf|wsh|hta|htaccess|htpasswd|config|"
    r"exe|dll|so|bin|elf|com|scr|msi|msp|reg|"
    r"zip|tar|gz|tgz|bz2|xz|7z|rar|iso|img|dmg)$",
    re.IGNORECASE,
)

# Path traversal in filename
_TRAVERSAL_FILENAME = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)

# Double-extension / MIME confusion (e.g., shell.php.jpg)
_DOUBLE_EXT = re.compile(
    r"\.(?:php\d?|phtml|phar|asp|aspx|jsp|jspx)\.",
    re.IGNORECASE,
)

# Detect multipart Content-Disposition header in the normalised body string.
# Captures the filename value up to the closing quote, semicolon, or end of line.
_CONTENT_DISPOSITION_STR = re.compile(
    r'content-disposition\s*:.*?filename\s*=\s*["\']?([^"\';\r\n]+)',
    re.IGNORECASE | re.DOTALL,
)

# Max filename length — many systems fail at 255; anything longer is suspicious.
_MAX_FILENAME_LEN = 255


# ── Patterns for raw-byte inspection (FileUploadNullByteRule) ─────────────────

# Matches the filename parameter in a raw multipart Content-Disposition header.
# Captures everything up to a closing quote, semicolon, CR, or LF.
_CONTENT_DISPOSITION_BYTES = re.compile(
    rb'content-disposition\s*:.*?filename\s*=\s*[b"\'"]?([^"\';\r\n\x00]*(?:\x00[^"\';\r\n]*)*)',
    re.IGNORECASE | re.DOTALL,
)

# Literal null byte in the filename bytes.
_NULL_BYTE_RAW = re.compile(rb"\x00")

# URL-encoded null byte (%00) — can appear literally in the raw bytes of the
# multipart body when the client sends it as text in the Content-Disposition
# line (e.g. filename="shell.php%00.jpg"), which is a common evasion technique.
# %2500 is a double-encoded form: the server decodes %25 → %, leaving %00 in
# the application layer.
_NULL_BYTE_ENCODED = re.compile(rb"%00|%2500", re.IGNORECASE)


def _extract_raw_filenames(raw_body: bytes) -> list:
    """
    Parse Content-Disposition filename values from raw multipart bytes.

    Returns a list of byte strings, one per file part found in the first
    _SCAN_LIMIT_RAW bytes. Stops after 50 parts to avoid pathological inputs.
    """
    chunk = raw_body[:_SCAN_LIMIT_RAW]
    filenames = []
    for i, m in enumerate(_CONTENT_DISPOSITION_BYTES.finditer(chunk)):
        if i >= 50:
            break
        filenames.append(m.group(1))
    return filenames


# ── Rule classes ──────────────────────────────────────────────────────────────

class FileUploadDangerousExtensionRule(Rule):
    """Block uploads with server-executable or archive-bomb file extensions."""

    RULE_ID = "974100"
    NAME = "File Upload — Dangerous Extension"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "multipart" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:_SCAN_LIMIT_STR]
        for m in _CONTENT_DISPOSITION_STR.finditer(body):
            filename = m.group(1).strip().rstrip('"\'')
            if _DANGEROUS_EXT.search(filename):
                return _upload_verdict(
                    self.RULE_ID,
                    f"Upload rejected: dangerous file extension in '{filename}'",
                    {"filename": filename[:200]},
                )
        return _clean(self.RULE_ID)


class FileUploadNullByteRule(Rule):
    """
    Detect null-byte injection in uploaded filenames (extension truncation bypass).

    Inspects request.raw_body — the original unmodified request bytes — so that
    literal \\x00 bytes in filenames are detected even though the normaliser
    strips them from the string representation (request.body).

    Also detects URL-encoded forms: %00 and double-encoded %2500 in the raw
    Content-Disposition line.

    Does NOT flag null bytes that appear only in file content; it only looks
    inside the Content-Disposition header line for each MIME part.
    """

    RULE_ID = "974105"
    NAME = "File Upload — Null-Byte Filename Bypass"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "multipart" not in ct:
            return _clean(self.RULE_ID)

        raw = getattr(request, "raw_body", b"")
        if not raw:
            return _clean(self.RULE_ID)

        for filename_bytes in _extract_raw_filenames(raw):
            if _NULL_BYTE_RAW.search(filename_bytes):
                filename_repr = filename_bytes[:200].decode("utf-8", errors="replace")
                return _upload_verdict(
                    self.RULE_ID,
                    "Literal null byte in upload filename (extension bypass attempt)",
                    {"filename": filename_repr},
                )
            if _NULL_BYTE_ENCODED.search(filename_bytes):
                filename_repr = filename_bytes[:200].decode("utf-8", errors="replace")
                return _upload_verdict(
                    self.RULE_ID,
                    "URL-encoded null byte (%00 / %2500) in upload filename",
                    {"filename": filename_repr},
                )
        return _clean(self.RULE_ID)


class FileUploadTraversalFilenameRule(Rule):
    """Detect path traversal sequences in uploaded filenames."""

    RULE_ID = "974110"
    NAME = "File Upload — Path Traversal in Filename"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "multipart" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:_SCAN_LIMIT_STR]
        for m in _CONTENT_DISPOSITION_STR.finditer(body):
            filename = m.group(1)
            if _TRAVERSAL_FILENAME.search(filename):
                return _upload_verdict(
                    self.RULE_ID,
                    "Path traversal in upload filename",
                    {"filename": filename[:200]},
                )
        return _clean(self.RULE_ID)


class FileUploadDoubleExtensionRule(Rule):
    """Detect double-extension filenames used to confuse server-side type checks."""

    RULE_ID = "974115"
    NAME = "File Upload — Double Extension MIME Confusion"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "multipart" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:_SCAN_LIMIT_STR]
        for m in _CONTENT_DISPOSITION_STR.finditer(body):
            filename = m.group(1).strip()
            if _DOUBLE_EXT.search(filename):
                return _upload_verdict(
                    self.RULE_ID,
                    f"Double-extension filename '{filename}' (MIME confusion attack)",
                    {"filename": filename[:200]},
                )
        return _clean(self.RULE_ID)


class FileUploadOversizedFilenameRule(Rule):
    """Detect filenames exceeding the maximum safe length."""

    RULE_ID = "974120"
    NAME = "File Upload — Oversized Filename"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "multipart" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:_SCAN_LIMIT_STR]
        for m in _CONTENT_DISPOSITION_STR.finditer(body):
            filename = m.group(1).strip().rstrip('"\'')
            if len(filename) > _MAX_FILENAME_LEN:
                return _upload_verdict(
                    self.RULE_ID,
                    f"Upload filename exceeds {_MAX_FILENAME_LEN} characters",
                    {"filename_length": len(filename), "filename_prefix": filename[:50]},
                )
        return _clean(self.RULE_ID)
