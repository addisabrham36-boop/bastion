"""
Path Traversal and Local File Inclusion (LFI) Rules (OWASP CRS 930xxx).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict


def _match_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    for field_label, value in request.iter_values():
        if not value:
            continue
        for pattern, reason in compiled_patterns:
            if pattern.search(value):
                return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
    return Verdict.clean(rule_id)


_ALL_TRAVERSAL_PATTERNS: List[Tuple[str, str]] = [
    (r"\.\.[/\\]", "Directory traversal sequence (../ or ..\\)"),
    (r"[/\\]\.\.(?:[/\\]|$)", "Directory traversal boundary (/../)"),
    (r"/(?:etc|private/etc)/(?:passwd|shadow|group|hosts|issue|master\.passwd)", "UNIX system file access attempt"),
    (r"/proc/(?:self|\d+)/(?:environ|cmdline|status|maps|cwd|fd)", "Linux /proc filesystem inspection"),
    (r"/var/log/(?:auth|syslog|messages|apache2|nginx|httpd)", "System log file access attempt"),
    (r"[a-zA-Z]:[/\\](?:windows|winnt|boot\.ini|inetpub|program\s*files)", "Windows system directory access"),
    (r"(?:^|[/\\]|\.\.)(?:win\.ini|boot\.ini|web\.config)(?:$|[/?#])", "Windows critical configuration file access"),
    (r"\bweb\.config\b", "web.config configuration file access"),
]
_COMPILED_ALL_TRAVERSAL = [(re.compile(p, re.IGNORECASE), r) for p, r in _ALL_TRAVERSAL_PATTERNS]


class TraversalRule(Rule):
    RULE_ID = "930120"
    NAME = "Path Traversal / LFI Guard"
    def match(self, request) -> Verdict: return _match_helper(self.RULE_ID, _COMPILED_ALL_TRAVERSAL, request)


class TraversalStandardRule(Rule):
    RULE_ID = "930100"
    NAME = "Path Traversal Standard Dot-Dot Sequence"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\.\.[/\\]|[/\\]\.\.(?:[/\\]|$)", re.I), "Directory traversal")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalMultiDepthRule(Rule):
    RULE_ID = "930110"
    NAME = "Path Traversal Multi-Depth Directory Escape"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"(?:\.\.[/\\]){3,}", re.I), "Deep directory traversal")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalUnixFilesRule(Rule):
    RULE_ID = "930121"
    NAME = "Path Traversal /etc/passwd & UNIX System Files"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/(?:etc|private/etc)/(?:passwd|shadow|group|hosts)", re.I), "UNIX system files access")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalProcFilesystemRule(Rule):
    RULE_ID = "930130"
    NAME = "Path Traversal Linux /proc Filesystem Inspection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/proc/(?:self|\d+)/", re.I), "/proc filesystem inspection")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalLogFilesRule(Rule):
    RULE_ID = "930140"
    NAME = "Path Traversal System & Service Log Disclosure"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/var/log/", re.I), "Log file access")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalWindowsFilesRule(Rule):
    RULE_ID = "930150"
    NAME = "Path Traversal Windows win.ini & Configuration Disclosure"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"(?:win\.ini|boot\.ini|web\.config)", re.I), "Windows config disclosure")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalWindowsDriveRule(Rule):
    RULE_ID = "930160"
    NAME = "Path Traversal Windows Drive Root Access"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"[a-zA-Z]:[/\\]windows", re.I), "Windows drive root access")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalNullByteRule(Rule):
    RULE_ID = "930170"
    NAME = "Path Traversal Null-Byte Truncation (%00)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"%00|\x00", re.I), "Null byte truncation")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalAbsolutePathRule(Rule):
    RULE_ID = "930180"
    NAME = "Path Traversal Absolute Root Directory Escape"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"^/(?:root|var/www|usr/share)/", re.I), "Absolute path escape")]
        return _match_helper(self.RULE_ID, p, request)


class TraversalEncodedSlashesRule(Rule):
    RULE_ID = "930190"
    NAME = "Path Traversal URL-Encoded Slashes Evasion"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"%2e%2e[%2f/]", re.I), "Encoded slashes traversal")]
        return _match_helper(self.RULE_ID, p, request)
