import re
from typing import List, Tuple

from .base import Rule, Verdict

_RCE_PATTERNS: List[Tuple[str, str]] = [
    (r"\$\([^\)]+\)", "UNIX shell command substitution $(...)"),
    (r"`[^`]+`", "UNIX shell backtick command substitution `...`"),
    (
        r"(?:;|\|\||&&|\||\n)\s*(?:whoami\b|uname(?:\s+-[a-z]+|\b)|id(?:\s+-[a-z]+|\s*$|\s*;|\s*\|)|cat\s+[/\w\.\-]+|ls\s+-[a-z]+|curl\s+https?:|wget\s+https?:|nc\s+-[a-z]+|chmod\s+[0-7]+|rm\s+-[a-z]*r|python[23]?\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|/bin/(?:sh|bash)|/usr/bin/)",
        "Chained shell command execution",
    ),
    (r"\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*['\"$`]", "Dangerous system execution function sink"),
    (r"(?:bash\s+-i|/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|nc\s+(?:-[a-z]*e\b|\d{1,3}\.\d{1,3}))", "Reverse shell payload attempt"),
    (r"\b(?:powershell(?:\.exe)?\s+-(?:enc|encodedcommand|executionpolicy|w|windowstyle))\b", "PowerShell encoded/obfuscated command execution"),
]

_COMPILED_RCE = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _RCE_PATTERNS]


class CommandInjectionRule(Rule):
    RULE_ID = "932100"
    NAME = "Remote Code Execution (RCE) Engine"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_RCE:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)

