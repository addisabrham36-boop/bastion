"""
Tests for Multipart / File Upload Integrity rules (974xxx).

Coverage requirements (per specification):
  - Multipart filename with literal null byte (\x00) is detected.
  - Filename containing %00 is detected.
  - Double-encoded %2500 is tested against the actual normalisation pipeline.
  - Normal filename (report.pdf) is accepted.
  - Legitimate binary file content containing null bytes does NOT trigger the
    filename rule (null bytes in file *content* are fine; only filenames matter).
  - NormalizedRequest.raw_body is byte-for-byte identical to the original input.
  - Normalised body string strips null bytes (documents normaliser behaviour).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.multipart_upload import (
    FileUploadDangerousExtensionRule,
    FileUploadNullByteRule,
    FileUploadTraversalFilenameRule,
    FileUploadDoubleExtensionRule,
    FileUploadOversizedFilenameRule,
)

BOUNDARY = b"----TestBoundary123"
CT = "multipart/form-data; boundary=----TestBoundary123"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_multipart(filename: bytes, file_content: bytes = b"data") -> bytes:
    """Build a minimal well-formed multipart body from raw filename bytes."""
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="'
        + filename
        + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + file_content
        + b"\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )


def _req_raw(filename: bytes, file_content: bytes = b"data"):
    """Construct a NormalizedRequest from raw bytes in the filename field."""
    body = _build_multipart(filename, file_content)
    return inspect_request(
        method="POST",
        path="/upload",
        headers={"content-type": CT},
        body=body,
    ).request


def _req_str(filename: str, file_content: bytes = b"data"):
    """Convenience: build from a Python string filename (encoded to UTF-8)."""
    return _req_raw(filename.encode("utf-8"), file_content)


def _safe_req(path="/", method="GET", headers=None):
    return inspect_request(
        method=method, path=path, headers=headers or {}, body=b""
    ).request


# ── FileUploadDangerousExtensionRule ──────────────────────────────────────────

class TestFileUploadDangerousExtensionRule:
    rule = FileUploadDangerousExtensionRule()

    def test_blocks_php_extension(self):
        assert self.rule.match(_req_str("shell.php")).blocked

    def test_blocks_phar_extension(self):
        assert self.rule.match(_req_str("exploit.phar")).blocked

    def test_blocks_asp_extension(self):
        assert self.rule.match(_req_str("webshell.asp")).blocked

    def test_blocks_exe_extension(self):
        assert self.rule.match(_req_str("malware.exe")).blocked

    def test_allows_jpg(self):
        assert not self.rule.match(_req_str("photo.jpg")).blocked

    def test_allows_pdf(self):
        assert not self.rule.match(_req_str("resume.pdf")).blocked

    def test_allows_png(self):
        assert not self.rule.match(_req_str("image.png")).blocked

    def test_ignores_non_multipart(self):
        assert not self.rule.match(_safe_req(path="/upload", method="POST")).blocked


# ── FileUploadNullByteRule ────────────────────────────────────────────────────

class TestFileUploadNullByteRule:
    rule = FileUploadNullByteRule()

    # ── Positive cases: must be detected ─────────────────────────────────────

    def test_blocks_literal_null_byte_in_filename(self):
        """
        A multipart body whose Content-Disposition filename contains a literal
        null byte (0x00) must be flagged.

        The normaliser strips \\x00 from the string copy (request.body) but
        request.raw_body retains the original bytes, which the rule inspects.
        """
        r = _req_raw(b"shell.php\x00.jpg")
        v = self.rule.match(r)
        assert v.blocked, (
            "Literal \\x00 in Content-Disposition filename must be detected via raw_body"
        )
        assert "null byte" in v.reason.lower()

    def test_blocks_percent00_in_filename(self):
        """
        A filename containing the literal ASCII text '%00' (URL-encoded null byte)
        must be flagged.  This is how attackers typically submit the evasion via HTTP.
        The raw multipart body contains the bytes b'%00' in the filename field.
        """
        r = _req_raw(b"shell.php%00.jpg")
        v = self.rule.match(r)
        assert v.blocked, (
            "URL-encoded null byte (%00) in Content-Disposition filename must be detected"
        )

    def test_blocks_double_encoded_percent2500_in_filename(self):
        """
        Double-encoded form: the raw bytes contain b'%2500'.
        When the application's first decoding pass runs:
            %25 → %   →   remaining string becomes %00
        The rule detects %2500 in the raw bytes as a documented evasion variant.
        """
        r = _req_raw(b"shell.php%2500.jpg")
        v = self.rule.match(r)
        assert v.blocked, (
            "Double-encoded null byte (%2500) in Content-Disposition filename must be detected"
        )

    # ── Normaliser behaviour: documented and tested ───────────────────────────

    def test_normalizer_strips_null_byte_from_body_string(self):
        """
        After normalisation, the string copy (request.body) must NOT contain \\x00.
        This documents that the normaliser provides early sanitisation, and that
        the null-byte rule cannot rely on request.body — it must use raw_body.
        """
        r = _req_raw(b"shell.php\x00.jpg")
        assert "\x00" not in r.body, (
            "Normaliser must strip \\x00 from the string body copy"
        )

    def test_raw_body_is_byte_for_byte_unchanged(self):
        """
        NormalizedRequest.raw_body must be identical to the original input bytes.
        No decoding, no stripping, no transformation.
        """
        original = _build_multipart(b"shell.php\x00.jpg")
        r = inspect_request(
            method="POST",
            path="/upload",
            headers={"content-type": CT},
            body=original,
        ).request
        assert r.raw_body == original, (
            "raw_body must be byte-for-byte identical to the original request bytes"
        )

    # ── Negative cases: must NOT be detected ─────────────────────────────────

    def test_allows_normal_filename(self):
        """A clean filename like report.pdf must not trigger the rule."""
        assert not self.rule.match(_req_str("report.pdf")).blocked

    def test_allows_binary_file_content_with_null_bytes(self):
        """
        Null bytes in the *file content* (e.g. a PNG or PDF) must NOT trigger
        this rule.  Only the Content-Disposition *filename* field is inspected.
        """
        # Build a multipart body where the filename is safe but the content
        # is a realistic binary blob full of null bytes (like a compiled binary).
        binary_content = b"\x00\xff\x00\xde\xad\xbe\xef\x00" * 128
        r = _req_raw(b"valid_report.pdf", file_content=binary_content)
        v = self.rule.match(r)
        assert not v.blocked, (
            "Null bytes in binary file *content* must not trigger the filename null-byte rule"
        )

    def test_ignores_non_multipart_request(self):
        """Rule must silently pass non-multipart requests."""
        r = _safe_req(path="/api/data", method="POST")
        assert not self.rule.match(r).blocked


# ── FileUploadTraversalFilenameRule ───────────────────────────────────────────

class TestFileUploadTraversalFilenameRule:
    rule = FileUploadTraversalFilenameRule()

    def test_blocks_traversal_in_filename(self):
        assert self.rule.match(_req_str("../../etc/passwd")).blocked

    def test_blocks_windows_traversal(self):
        assert self.rule.match(_req_str("..\\..\\windows\\system32")).blocked

    def test_allows_normal_filename(self):
        assert not self.rule.match(_req_str("document.docx")).blocked


# ── FileUploadDoubleExtensionRule ─────────────────────────────────────────────

class TestFileUploadDoubleExtensionRule:
    rule = FileUploadDoubleExtensionRule()

    def test_blocks_php_jpg_double_ext(self):
        assert self.rule.match(_req_str("shell.php.jpg")).blocked

    def test_blocks_asp_png(self):
        assert self.rule.match(_req_str("shell.asp.png")).blocked

    def test_allows_normal_double_ext(self):
        assert not self.rule.match(_req_str("archive.tar.gz")).blocked

    def test_allows_jpg(self):
        assert not self.rule.match(_req_str("photo.jpg")).blocked


# ── FileUploadOversizedFilenameRule ──────────────────────────────────────────

class TestFileUploadOversizedFilenameRule:
    rule = FileUploadOversizedFilenameRule()

    def test_blocks_oversized_filename(self):
        long_name = "a" * 300 + ".txt"
        assert self.rule.match(_req_str(long_name)).blocked

    def test_allows_normal_filename(self):
        assert not self.rule.match(_req_str("normal_file.txt")).blocked

    def test_allows_max_length_filename(self):
        # Exactly 255 chars should be allowed
        max_name = "a" * 251 + ".txt"
        assert not self.rule.match(_req_str(max_name)).blocked
