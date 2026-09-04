"""
Security Scanner & Automated Attack Tool Detection Rules (OWASP CRS 913xxx).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict


def _match_ua_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    ua = (request.headers or {}).get("user-agent", "")
    if not ua:
        return Verdict.clean(rule_id)
    for pattern, reason in compiled_patterns:
        if pattern.search(ua):
            return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": "header:user-agent", "matched_value": ua[:200]})
    return Verdict.clean(rule_id)


def _match_path_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    if request.path:
        for pattern, reason in compiled_patterns:
            if pattern.search(request.path):
                return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": "path", "matched_value": request.path[:200]})
    for key, values in (request.query_params or {}).items():
        for val in values:
            if val and ("/" in val or "\\" in val or "." in val):
                for pattern, reason in compiled_patterns:
                    if pattern.search(val):
                        return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": f"query:{key}", "matched_value": val[:200]})
    return Verdict.clean(rule_id)


_ALL_SCANNER_UAS = [
    (r"\b(?:sqlmap|nikto|burpsuite|owasp[\s-]?zap|acunetix|appscan|netsparker|qualys|nessus|openvas|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|feroxbuster|wfuzz|ffuf|skipfish|w3af|wpscan|joomscan|metasploit|cobaltstrike|hydra|medusa)\b", "Security scanner / vulnerability probing User-Agent signature"),
]
_C_ALL_SCANNER_UAS = [(re.compile(p, re.I), r) for p, r in _ALL_SCANNER_UAS]


class ScannerSignatureRule(Rule):
    RULE_ID = "913100"
    NAME = "Security Scanner User-Agent Detection"
    def match(self, request) -> Verdict: return _match_ua_helper(self.RULE_ID, _C_ALL_SCANNER_UAS, request)


class ScannerSQLMapRule(Rule):
    RULE_ID = "913101"
    NAME = "Scanner SQLMap Automated Injection Detection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bsqlmap\b", re.I), "SQLMap scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerNiktoRule(Rule):
    RULE_ID = "913102"
    NAME = "Scanner Nikto Web Vulnerability Scanner"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bnikto\b", re.I), "Nikto scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerBurpZAPRule(Rule):
    RULE_ID = "913103"
    NAME = "Scanner Burp Suite & OWASP ZAP Detection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:burpsuite|owasp[\s-]?zap)\b", re.I), "Burp/ZAP scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerCommercialRule(Rule):
    RULE_ID = "913104"
    NAME = "Scanner Commercial Vulnerability Scanners"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:acunetix|appscan|netsparker|qualys|nessus|openvas)\b", re.I), "Commercial scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerPortScannersRule(Rule):
    RULE_ID = "913105"
    NAME = "Scanner Nmap / Masscan / ZGrab Network Probers"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:nmap|masscan|zgrab)\b", re.I), "Network port scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerNucleiRule(Rule):
    RULE_ID = "913106"
    NAME = "Scanner Nuclei Template Scanner"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bnuclei\b", re.I), "Nuclei scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerFuzzersRule(Rule):
    RULE_ID = "913107"
    NAME = "Scanner Directory & Content Fuzzers"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:dirbuster|gobuster|feroxbuster|wfuzz|ffuf|skipfish|w3af)\b", re.I), "Directory fuzzer")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerCMSRule(Rule):
    RULE_ID = "913108"
    NAME = "Scanner CMS Vulnerability Probers (WPScan)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:wpscan|joomscan|droopescan)\b", re.I), "CMS scanner")]
        return _match_ua_helper(self.RULE_ID, p, request)


class ScannerExploitFrameworkRule(Rule):
    RULE_ID = "913109"
    NAME = "Scanner Metasploit & Exploit Frameworks"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:metasploit|cobaltstrike|havoc)\b", re.I), "Exploit framework")]
        return _match_ua_helper(self.RULE_ID, p, request)


class MaliciousBotRule(Rule):
    RULE_ID = "913110"
    NAME = "Malicious Bot & Bad Crawler Detection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:libwww-perl|python-urllib|scrapy|shodan|censys|whatweb)\b", re.I), "Malicious bot User-Agent")]
        return _match_ua_helper(self.RULE_ID, p, request)


_ALL_ATTACK_PATHS = [
    (r"/\.env\b", "Environment secrets file probe (/.env)"),
    (r"/config\.(?:json|yml|yaml|ini)\b", "Configuration file exposure probe"),
    (r"/\.git/", "Git version control directory probe (/.git/)"),
    (r"/\.svn/", "SVN repository directory probe (/.svn/)"),
    (r"/phpmyadmin\b|/pma\b|/adminer\.php\b", "Database administration panel probe (/phpmyadmin)"),
    (r"/actuator/(?:env|health|metrics|heapdump|loggers)", "Spring Boot Actuator inspection probe"),
    (r"/(?:shell|cmd|c99|r57|alfa|wso|b374k|mini)\.php\b", "Known web shell backdoor filename probe"),
    (r"/wp-login\.php\b|/wp-admin\b", "WordPress administrative login probe"),
]
_C_ALL_ATTACK_PATHS = [(re.compile(p, re.I), r) for p, r in _ALL_ATTACK_PATHS]


class AttackToolPathRule(Rule):
    RULE_ID = "913120"
    NAME = "Attack Tool Path & Probing Detection"
    def match(self, request) -> Verdict: return _match_path_helper(self.RULE_ID, _C_ALL_ATTACK_PATHS, request)


class AttackPathSecretsRule(Rule):
    RULE_ID = "913121"
    NAME = "Probing Sensitive Env Files & Credentials"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/\.env\b|/config\.(?:json|yml|ini)\b", re.I), "Secrets probe")]
        return _match_path_helper(self.RULE_ID, p, request)


class AttackPathVCSRule(Rule):
    RULE_ID = "913122"
    NAME = "Probing Version Control Repositories (.git)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/\.git/|/\.svn/", re.I), "VCS directory probe")]
        return _match_path_helper(self.RULE_ID, p, request)


class AttackPathDBPanelRule(Rule):
    RULE_ID = "913123"
    NAME = "Probing Database Admin Panels (phpMyAdmin)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/phpmyadmin\b|/adminer\.php\b", re.I), "DB panel probe")]
        return _match_path_helper(self.RULE_ID, p, request)


class AttackPathActuatorRule(Rule):
    RULE_ID = "913124"
    NAME = "Probing Server Metrics & Spring Actuator"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/actuator/|/server-status\b", re.I), "Actuator/Metrics probe")]
        return _match_path_helper(self.RULE_ID, p, request)


class AttackPathWebShellRule(Rule):
    RULE_ID = "913125"
    NAME = "Probing Web Shells & Administrative Logins"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"/(?:shell|cmd|c99|r57)\.php\b|/wp-login\.php\b", re.I), "Web shell/login probe")]
        return _match_path_helper(self.RULE_ID, p, request)
