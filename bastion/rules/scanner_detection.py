"""
Security scanner and attack-tool detection rules (OWASP CRS 913xxx).

Covers:
- 913100  ScannerSignatureRule  – known security scanner User-Agent strings
- 913110  MaliciousBotRule      – known malicious bots / bad crawlers
- 913120  AttackToolPathRule    – common attack-tool URL paths / probes
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 913100 – Security scanner User-Agent signatures
# ---------------------------------------------------------------------------

_SCANNER_UA_PATTERNS: List[Tuple[str, str]] = [
    (r"\bnikto\b", "Nikto vulnerability scanner"),
    (r"\bnessus\b", "Nessus vulnerability scanner"),
    (r"\bopenvas\b", "OpenVAS vulnerability scanner"),
    (r"\bnmap\b", "Nmap network scanner"),
    (r"\bmasscan\b", "Masscan port scanner"),
    (r"\bacunetix\b", "Acunetix web vulnerability scanner"),
    (r"\bappscan\b", "IBM AppScan web scanner"),
    (r"\bburpsuite\b", "Burp Suite web security tool"),
    (r"\bsqlmap\b", "SQLMap automated SQL injection tool"),
    (r"\bowasp[\s-]?zap\b", "OWASP ZAP web application scanner"),
    (r"\bw3af\b", "w3af web application attack framework"),
    (r"\bskipfish\b", "Skipfish web application security scanner"),
    (r"\bdirbuster\b", "DirBuster directory brute-force tool"),
    (r"\bgobuster\b", "Gobuster directory/DNS brute-force tool"),
    (r"\bferoxbuster\b", "Feroxbuster content discovery tool"),
    (r"\bwfuzz\b", "Wfuzz web fuzzer"),
    (r"\bffuf\b", "Ffuf web fuzzer"),
    (r"\bhydra\b", "Hydra credential brute-force tool"),
    (r"\bmedusa\b", "Medusa credential brute-force tool"),
    (r"\bmetasploit\b", "Metasploit exploitation framework"),
    (r"\bnuclei\b", "Nuclei template-based scanner"),
    (r"\bzgrab\b", "ZGrab network scanner"),
    (r"\bwhatweb\b", "WhatWeb web technology fingerprinter"),
    (r"\bwpscan\b", "WPScan WordPress vulnerability scanner"),
    (r"\bjoomscan\b", "JoomScan Joomla vulnerability scanner"),
]
_COMPILED_SCANNER_UA = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _SCANNER_UA_PATTERNS
]

# ---------------------------------------------------------------------------
# 913110 – Malicious bots / bad crawlers
# ---------------------------------------------------------------------------

_MALICIOUS_BOT_PATTERNS: List[Tuple[str, str]] = [
    (r"\bpython-requests\b", "Automated Python requests library (bot/scraper)"),
    (r"\bcurl\b.*\bbash\b", "curl piped to bash – likely exploit delivery"),
    (r"\blibwww-perl\b", "libwww-perl automated HTTP client"),
    (r"\bpython-urllib\b", "python-urllib automated HTTP client"),
    (r"\bgo-http-client\b", "Go HTTP client (bot/scanner)"),
    (r"\bscrapy\b", "Scrapy web scraping framework"),
    (r"\bzgrab\b", "ZGrab automated network scanner"),
    (r"\bmasscan\b", "Masscan high-speed port scanner"),
    (r"\bshodan\b", "Shodan internet-wide scanner"),
]
_COMPILED_MALICIOUS_BOT = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _MALICIOUS_BOT_PATTERNS
]

# ---------------------------------------------------------------------------
# 913120 – Common attack-tool paths / probing patterns
# ---------------------------------------------------------------------------

_ATTACK_PATH_PATTERNS: List[Tuple[str, str]] = [
    (r"/wp-admin\b", "WordPress admin panel probe"),
    (r"/wp-login\.php\b", "WordPress login page probe"),
    (r"/\.git/", "Git repository exposure probe"),
    (r"/\.env\b", "Environment file disclosure probe"),
    (r"/phpmyadmin\b", "phpMyAdmin panel probe"),
    (r"/\.htaccess\b", "Apache .htaccess disclosure probe"),
    (r"/admin/config\b", "Admin configuration endpoint probe"),
    (r"/server-status\b", "Apache server-status probe"),
    (r"/actuator/", "Spring Boot Actuator endpoint probe"),
    (r"/api/swagger\b", "Swagger API documentation probe"),
    (r"/api/v\d+/swagger\b", "Versioned Swagger API probe"),
    (r"\bxmlrpc\.php\b", "WordPress XML-RPC probe"),
    (r"/shell\.php\b", "Web shell probe (shell.php)"),
    (r"/cmd\.php\b", "Web shell probe (cmd.php)"),
    (r"/webshell\b", "Web shell probe"),
    (r"\beval\.php\b", "Eval PHP web shell probe"),
    (r"\bc99\.php\b", "c99 web shell probe"),
    (r"\br57\.php\b", "r57 web shell probe"),
]
_COMPILED_ATTACK_PATH = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _ATTACK_PATH_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class ScannerSignatureRule(Rule):
    """Detect security scanner User-Agent signatures (OWASP CRS 913100)."""

    RULE_ID = "913100"
    NAME = "Security Scanner User-Agent Detection"

    def match(self, request) -> Verdict:
        ua = (request.headers or {}).get("user-agent", "")
        if not ua:
            return Verdict.clean(self.RULE_ID)
        for pattern, reason in _COMPILED_SCANNER_UA:
            if pattern.search(ua):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=reason,
                    meta={"field": "header:user-agent", "matched_value": ua[:200]},
                )
        return Verdict.clean(self.RULE_ID)


class MaliciousBotRule(Rule):
    """Detect known malicious bots and bad crawlers in User-Agent (OWASP CRS 913110)."""

    RULE_ID = "913110"
    NAME = "Malicious Bot / Bad Crawler Detection"

    def match(self, request) -> Verdict:
        ua = (request.headers or {}).get("user-agent", "")
        if not ua:
            return Verdict.clean(self.RULE_ID)
        for pattern, reason in _COMPILED_MALICIOUS_BOT:
            if pattern.search(ua):
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=reason,
                    meta={"field": "header:user-agent", "matched_value": ua[:200]},
                )
        return Verdict.clean(self.RULE_ID)


class AttackToolPathRule(Rule):
    """Detect common attack-tool URL paths and probing attempts (OWASP CRS 913120)."""

    RULE_ID = "913120"
    NAME = "Attack Tool Path / Probing Detection"

    def match(self, request) -> Verdict:
        # Check path and any query values for known attack paths
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_ATTACK_PATH:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
