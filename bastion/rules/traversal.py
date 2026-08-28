"""
Path Traversal and LFI detection rule (OWASP CRS 930120).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_TRAVERSAL_PATTERNS: List[Tuple[str, str]] = [
    (r"\.\.[/\\]", "Directory traversal sequence (../ or ..\\)"),
    (r"[/\\]\.\.(?:[/\\]|$)", "Directory traversal boundary (/../)"),
    (r"/(?:etc|private/etc)/(?:passwd|shadow|group|hosts|issue|master\.passwd)", "UNIX system file access attempt"),
    (r"/proc/self/(?:environ|cmdline|status|maps|cwd|fd)", "Linux /proc filesystem inspection"),
    (r"/var/log/(?:auth|syslog|messages|apache2|nginx|httpd)", "System log file access attempt"),
    (r"[a-zA-Z]:[/\\](?:windows|winnt|boot\.ini|inetpub|program\s*files)", "Windows system directory access"),
    (r"(?:^|[/\\]|\.\.)(?:win\.ini|boot\.ini|web\.config)(?:$|[/?#])", "Windows critical configuration file access"),
]

_COMPILED_TRAVERSAL = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _TRAVERSAL_PATTERNS]


class TraversalRule(Rule):
    RULE_ID = "930120"
    NAME = "Path Traversal / LFI Guard"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_TRAVERSAL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
