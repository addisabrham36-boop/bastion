"""
Remote Code Execution (RCE) and OS Command Injection Rules (OWASP CRS 932xxx).
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


_ALL_RCE_PATTERNS: List[Tuple[str, str]] = [
    (r"\$\([a-zA-Z0-9_\-/\.]+\s*", "Unix subshell command substitution $(...)"),
    (r"`[^`\r\n]+`", "Unix backtick command execution `...`"),
    (r"[;&|]\s*(?:cat\s+|ls\s+|id\b|whoami\b|uname\b|curl\s+|wget\s+|chmod\s+|rm\s+)", "Chained command execution with system binary"),
    (r"\|\|\s*(?:id|whoami|cat|bash|sh|curl|wget)\b", "Logical OR command chain (||) execution"),
    (r"&&\s*(?:id|whoami|cat|bash|sh|curl|wget)\b", "Logical AND command chain (&&) execution"),
    (r"\b(?:/usr/bin/id|/bin/sh|/bin/bash|/usr/bin/whoami|/bin/cat)\b", "Direct absolute path invocation of system shell"),
    (r"\bcmd(?:\.exe)?\s*/[ckq]\s+", "Windows cmd.exe shell invocation (/c /k)"),
    (r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", "Bash /dev/tcp socket reverse shell"),
    (r"\bnc\s+(?:-e\s+/bin/|-[a-zA-Z]*e\s+)", "Netcat traditional reverse shell execution (-e /bin/sh)"),
    (r"\(\s*\)\s*\{\s*:\s*;\s*\}\s*;", "Shellshock bash environment vulnerability (CVE-2014-6271)"),
    (r"\b(?:passthru|shell_exec|exec|system|popen|proc_open)\s*\(\s*['\"`\$]", "Web application execution function sink with argument"),
]
_COMPILED_ALL_RCE = [(re.compile(p, re.IGNORECASE), r) for p, r in _ALL_RCE_PATTERNS]


class CommandInjectionRule(Rule):
    RULE_ID = "932100"
    NAME = "Remote Code Execution (RCE) Comprehensive Engine"
    def match(self, request) -> Verdict: return _match_helper(self.RULE_ID, _COMPILED_ALL_RCE, request)


class RCESubshellRule(Rule):
    RULE_ID = "932101"
    NAME = "RCE Unix Command Substitution $(...)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\$\([a-zA-Z0-9_\-/\.]+\s*|`[^`\r\n]+`", re.I), "Command substitution")]
        return _match_helper(self.RULE_ID, p, request)


class RCECommandChainingRule(Rule):
    RULE_ID = "932110"
    NAME = "RCE Shell Command Chaining Operators"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"[;&|]\s*(?:cat\s+|ls\s+|id\b|whoami\b|uname\b)", re.I), "Chained command execution")]
        return _match_helper(self.RULE_ID, p, request)


class RCESystemUtilitiesRule(Rule):
    RULE_ID = "932120"
    NAME = "RCE System Binary / Utility Invocation"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:/usr/bin/id|/bin/sh|/bin/bash)\b", re.I), "System utility invocation")]
        return _match_helper(self.RULE_ID, p, request)


class RCEWindowsCommandRule(Rule):
    RULE_ID = "932130"
    NAME = "RCE Windows cmd.exe & PowerShell Execution"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bcmd(?:\.exe)?\s*/[ckq]\s+|\bpowershell\b", re.I), "Windows command execution")]
        return _match_helper(self.RULE_ID, p, request)


class RCEReverseShellRule(Rule):
    RULE_ID = "932140"
    NAME = "RCE Outbound Reverse & Bind Shells"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/dev/tcp/|\bnc\s+-[a-zA-Z]*e\b|\bmkfifo\b", re.I), "Reverse shell payload")]
        return _match_helper(self.RULE_ID, p, request)


class RCEShellshockRule(Rule):
    RULE_ID = "932150"
    NAME = "RCE Shellshock Bash Vulnerability"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\(\s*\)\s*\{\s*:\s*;\s*\}\s*;", re.I), "Shellshock exploit")]
        return _match_helper(self.RULE_ID, p, request)


class RCEWebShellFunctionRule(Rule):
    RULE_ID = "932160"
    NAME = "RCE Web Shell Execution Sinks"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:passthru|shell_exec|system|popen)\s*\(", re.I), "Web shell execution sink")]
        return _match_helper(self.RULE_ID, p, request)


class RCEPrivilegeEscalationRule(Rule):
    RULE_ID = "932170"
    NAME = "RCE Privilege Escalation & Sudo Probes"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bsudo\s+(?:-l|-i|-u\s+root)|/etc/sudoers", re.I), "Privilege escalation probe")]
        return _match_helper(self.RULE_ID, p, request)


class RCEPowerShellCradleRule(Rule):
    RULE_ID = "932180"
    NAME = "RCE PowerShell Download Cradle & IEX"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:IEX|Invoke-Expression)\b|\bDownloadString\b", re.I), "PowerShell download cradle")]
        return _match_helper(self.RULE_ID, p, request)
