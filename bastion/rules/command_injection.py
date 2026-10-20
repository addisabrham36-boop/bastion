"""
Remote Code Execution (RCE) and OS Command Injection Rules (OWASP CRS 932xxx).
Detects standalone binaries, shell utilities, chained operators, subshells, and reverse shells.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict


def _match_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    for field_label, value in request.iter_values():
        if not value:
            continue
        # Skip bare standalone binary matching on user-agent header (e.g. curl/8.x, python-requests)
        if field_label.startswith("header:user-agent") and rule_id in ("932100", "932120"):
            continue
        # Skip bare standalone utility matching on multipart bodies to prevent false positives on MIME field names (e.g. name="file", Content-Type:)
        if field_label == "body" and "multipart/" in request.headers.get("content-type", "").lower() and rule_id in ("932120", "932130"):
            continue
        # Also test de-obfuscated value (stripping internal quotes and backslashes)
        cleaned_value = re.sub(r"['\"\\\\]", "", value)
        for pattern, reason in compiled_patterns:
            if pattern.search(value) or pattern.search(cleaned_value):
                return Verdict(
                    blocked=True,
                    rule_id=rule_id,
                    reason=reason,
                    meta={"field": field_label, "matched_value": value[:200]},
                )
    return Verdict.clean(rule_id)


_SYSTEM_COMMANDS = (
    r"whoami|id|uname|hostname|pwd|ls|dir|cat|head|tail|more|less|grep|egrep|fgrep|awk|sed|find|"
    r"xargs|cut|sort|uniq|wc|stat|file|strings|od|hexdump|xxd|dd|touch|cp|mv|rm|rmdir|mkdir|chmod|"
    r"chown|ln|tar|gzip|gunzip|zip|unzip|curl|wget|nc|ncat|netcat|socat|telnet|ftp|ssh|scp|sftp|rsync|"
    r"ping|traceroute|dig|nslookup|ifconfig|ip|netstat|ss|arp|iptables|ufw|ps|top|htop|kill|killall|pkill|"
    r"crontab|systemctl|journalctl|reboot|shutdown|poweroff|dmesg|uptime|free|df|du|useradd|usermod|"
    r"groupadd|passwd|shadow|sudo|su|chroot|bash|sh|zsh|ksh|csh|tcsh|dash|fish|python\d*|perl|ruby|php|"
    r"node|gcc|g\+\+|make|echo|cmd(?:\.exe)?|powershell|pwsh|type|tasklist|taskkill|vssadmin|certutil|wmic|bitsadmin|mshta"
)

_ALL_RCE_PATTERNS: List[Tuple[str, str]] = [
    # 1. Command substitution & subshells: $(...), `...`, ${...}
    (r"\$\([^\)]*\)", "Unix subshell command substitution $(...)"),
    (r"`[^`\r\n]+`", "Unix backtick command execution `...`"),
    (r"\$\{[^}]*\}", "Shell variable/command expansion ${...}"),

    # 2. Command chaining operators: ;, &, &&, |, ||, |& followed by a system command
    (rf"(?:[;&|]|&&|\|\||\|&)\s*(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/|/usr/local/bin/)?(?:{_SYSTEM_COMMANDS})\b", "Chained shell command execution"),

    # 3. Direct path invocation of system binaries
    (rf"(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/|/usr/local/bin/)(?:{_SYSTEM_COMMANDS})\b", "Direct binary path execution"),

    # 4. Standalone command execution or command starting line
    (rf"(?:^|\n|\r)\s*(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/|/usr/local/bin/)?(?:{_SYSTEM_COMMANDS})\b(?:\s+.*)?$", "Direct system command execution"),

    # 5. IP route / address command
    (r"(?:^|[;&|]|\s)\bip\s+(?:a|addr|link|route|neigh|rule|maddr)\b", "IP networking utility execution"),

    # 6. Execution sinks in scripts
    (r"\b(?:passthru|shell_exec|exec|system|popen|proc_open|eval)\s*\(\s*['\"`\$\w]", "Web shell code execution sink"),

    # 7. Reverse shells and network pipes
    (r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", "Bash /dev/tcp socket reverse shell"),
    (r"\bnc(?:\.traditional)?\s+-[a-zA-Z]*e\s+", "Netcat reverse shell execution"),
    (r"\bmkfifo\s+", "Named pipe creation for reverse shell"),

    # 8. Windows cmd & PowerShell invocations
    (r"\bcmd(?:\.exe)?\s*/[ckq]\s+", "Windows cmd.exe shell invocation"),
    (r"\b(?:IEX|Invoke-Expression|DownloadString|Start-Process)\b", "PowerShell execution / download cradle"),

    # 9. Shellshock
    (r"\(\s*\)\s*\{\s*:\s*;\s*\}\s*;", "Shellshock bash vulnerability (CVE-2014-6271)"),
]
_COMPILED_ALL_RCE = [(re.compile(p, re.IGNORECASE), r) for p, r in _ALL_RCE_PATTERNS]


class CommandInjectionRule(Rule):
    RULE_ID = "932100"
    NAME = "Remote Code Execution (RCE) Comprehensive Engine"

    def match(self, request) -> Verdict:
        return _match_helper(self.RULE_ID, _COMPILED_ALL_RCE, request)


class RCESubshellRule(Rule):
    RULE_ID = "932101"
    NAME = "RCE Unix Command Substitution $(...)"

    def match(self, request) -> Verdict:
        p = [(re.compile(r"\$\([^\)]*\)|`[^`\r\n]+`|\$\{[^}]*\}", re.I), "Command substitution")]
        return _match_helper(self.RULE_ID, p, request)


class RCECommandChainingRule(Rule):
    RULE_ID = "932110"
    NAME = "RCE Shell Command Chaining Operators"

    def match(self, request) -> Verdict:
        p = [(re.compile(rf"(?:[;&|]|&&|\|\||\|&)\s*(?:{_SYSTEM_COMMANDS})\b", re.I), "Chained command execution")]
        return _match_helper(self.RULE_ID, p, request)


class RCESystemUtilitiesRule(Rule):
    RULE_ID = "932120"
    NAME = "RCE System Binary / Utility Invocation"

    def match(self, request) -> Verdict:
        p = [(re.compile(rf"(?:^|\n|\r|\b)(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/)?(?:{_SYSTEM_COMMANDS})\b", re.I), "System utility invocation")]
        return _match_helper(self.RULE_ID, p, request)


class RCEWindowsCommandRule(Rule):
    RULE_ID = "932130"
    NAME = "RCE Windows cmd.exe & PowerShell Execution"

    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bcmd(?:\.exe)?\s*/[ckq]\s+|\bpowershell\b|\bdir\b|\btype\b", re.I), "Windows command execution")]
        return _match_helper(self.RULE_ID, p, request)


class RCEReverseShellRule(Rule):
    RULE_ID = "932140"
    NAME = "RCE Outbound Reverse & Bind Shells"

    def match(self, request) -> Verdict:
        p = [(re.compile(r"/dev/tcp/|\bnc(?:\.traditional)?\s+-[a-zA-Z]*e\b|\bmkfifo\b", re.I), "Reverse shell payload")]
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
        p = [(re.compile(r"\b(?:passthru|shell_exec|system|popen|proc_open|eval)\s*\(", re.I), "Web shell execution sink")]
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
        p = [(re.compile(r"\b(?:IEX|Invoke-Expression|DownloadString|Start-Process)\b", re.I), "PowerShell download cradle")]
        return _match_helper(self.RULE_ID, p, request)
