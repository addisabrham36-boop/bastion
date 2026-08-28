"""
SQL Injection (SQLi) Detection Rules (OWASP CRS 942xxx).
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


_ALL_SQLI_PATTERNS: List[Tuple[str, str]] = [
    (r"\bunion(?:\s+|/\*.*?\*/)+(?:all(?:\s+|/\*.*?\*/)+)?select\b", "UNION-based SQL injection attempt"),
    (r"un/\*.*?\*/ion", "Comment-obfuscated UNION keyword"),
    (r"sel/\*.*?\*/ect", "Comment-obfuscated SELECT keyword"),
    (r"'\s+or\s+'[^']+'\s*=\s*'[^']*", "Classic quoted boolean tautology (' OR 'x'='x')"),
    (r"'\s+or\s+1\s*=\s*1", "Quoted tautology (' OR 1=1)"),
    (r"'\s+or\s+''\s*=\s*'", "Empty quote tautology (' OR ''=')"),
    (r"\"\s+or\s+\"[^\"]+\"\s*=\s*\"[^\"]*", "Double-quoted boolean tautology"),
    (r"\b(?:or|and)\s+\(?\s*\d+\s*=\s*\d+\s*\)?\s*(?:--|#|/\*|;|$)", "Numeric SQL tautology (OR 1=1)"),
    (r"\bwaitfor\s+delay\s+['\"]", "MSSQL time-based blind SQLi (WAITFOR DELAY)"),
    (r"\b(?:pg_)?sleep\s*\(\s*\d+\s*\)", "Time-based blind SQLi (SLEEP / pg_sleep)"),
    (r"\bbenchmark\s*\(\s*\d+\s*,", "MySQL benchmark time-based SQLi (BENCHMARK)"),
    (r"\bextractvalue\s*\(", "MySQL error-based SQLi (extractvalue)"),
    (r"\bupdatexml\s*\(", "MySQL error-based SQLi (updatexml)"),
    (r";\s*(?:drop\s+table|drop\s+database|truncate\s+table|alter\s+table)\b", "Destructive stacked SQL query (DROP/TRUNCATE)"),
    (r";\s*(?:insert\s+into|update\s+[a-zA-Z0-9_]+\s+set|delete\s+from)\b", "Stacked SQL modification query"),
    (r"\binformation_schema\.(?:tables|columns|schemata|views|routines)\b", "Database schema enumeration (information_schema)"),
    (r"\bload_file\s*\(", "MySQL LOAD_FILE() filesystem disclosure"),
    (r"\binto\s+(?:out|dump)file\s+['\"]", "MySQL INTO OUTFILE shell write attempt"),
    (r"\bpg_read_file\s*\(", "PostgreSQL pg_read_file() filesystem disclosure"),
    (r"\bxp_cmdshell\b", "MSSQL xp_cmdshell command execution attempt"),
    (r"\butl_http\.", "Oracle UTL_HTTP out-of-band extraction"),
    (r"\bsqlite_version\s*\(", "SQLite version disclosure probe"),
    (r"\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\)", "SQL CHAR() multi-byte string reconstruction"),
]
_COMPILED_ALL_SQLI = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _ALL_SQLI_PATTERNS]


class SQLiRule(Rule):
    RULE_ID = "942100"
    NAME = "SQL Injection (SQLi) Comprehensive Shield"
    def match(self, request) -> Verdict: return _match_helper(self.RULE_ID, _COMPILED_ALL_SQLI, request)


class SQLiUnionRule(Rule):
    RULE_ID = "942101"
    NAME = "SQLi UNION-Based Query Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bunion(?:\s+|/\*.*?\*/)+(?:all(?:\s+|/\*.*?\*/)+)?select\b", re.I), "UNION-based SQL injection")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiBooleanTautologyRule(Rule):
    RULE_ID = "942110"
    NAME = "SQLi Boolean Tautology Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"'\s+or\s+'[^']+'\s*=\s*'[^']*|'\s+or\s+1\s*=\s*1", re.I), "Boolean tautology")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiNumericTautologyRule(Rule):
    RULE_ID = "942120"
    NAME = "SQLi Numeric Tautology Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:or|and)\s+\(?\s*\d+\s*=\s*\d+\s*\)?\s*(?:--|#|/\*|;|$)", re.I), "Numeric tautology")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiTimeBasedRule(Rule):
    RULE_ID = "942130"
    NAME = "SQLi Time-Based Blind Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bwaitfor\s+delay\b|\b(?:pg_)?sleep\s*\(|\bbenchmark\s*\(", re.I), "Time-based blind SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiErrorBasedRule(Rule):
    RULE_ID = "942140"
    NAME = "SQLi Error-Based Extraction"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bextractvalue\s*\(|\bupdatexml\s*\(|\bconvert\s*\(\s*(?:int|varchar)", re.I), "Error-based SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiStackedQueriesRule(Rule):
    RULE_ID = "942150"
    NAME = "SQLi Stacked DDL/DML Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r";\s*(?:drop\s+table|truncate\s+table|alter\s+table|delete\s+from)\b", re.I), "Stacked queries")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiSchemaEnumerationRule(Rule):
    RULE_ID = "942160"
    NAME = "SQLi Schema & Metadata Enumeration"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\binformation_schema\.|\bsys\.tables\b|\bsqlite_master\b", re.I), "Schema enumeration")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiMySQLDialectRule(Rule):
    RULE_ID = "942170"
    NAME = "SQLi MySQL Specific Functions"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bload_file\s*\(|\binto\s+(?:out|dump)file\b", re.I), "MySQL specific SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiPostgreSQLDialectRule(Rule):
    RULE_ID = "942180"
    NAME = "SQLi PostgreSQL Specific Functions"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bpg_read_file\s*\(|\bpg_catalog\.", re.I), "PostgreSQL specific SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiMSSQLDialectRule(Rule):
    RULE_ID = "942190"
    NAME = "SQLi MSSQL Specific Procedures"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bxp_cmdshell\b|\bsp_executesql\b", re.I), "MSSQL specific SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiOracleDialectRule(Rule):
    RULE_ID = "942200"
    NAME = "SQLi Oracle Specific Packages"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\butl_http\.|\butl_file\.", re.I), "Oracle specific SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiSQLiteDialectRule(Rule):
    RULE_ID = "942210"
    NAME = "SQLi SQLite Specific Functions"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bsqlite_version\s*\(|\battach\s+database\b", re.I), "SQLite specific SQLi")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiCommentObfuscationRule(Rule):
    RULE_ID = "942220"
    NAME = "SQLi Comment-Based Obfuscation"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"un/\*.*?\*/ion|sel/\*.*?\*/ect|\bunion/\*.*?\*/select\b", re.I), "Comment obfuscation")]
        return _match_helper(self.RULE_ID, p, request)


class SQLiHexEncodingRule(Rule):
    RULE_ID = "942230"
    NAME = "SQLi Hex & Char Encoding Bypass"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bchar\s*\(\s*\d+\s*,\s*\d+|\bchr\s*\(\s*\d+\s*\)", re.I), "Hex/Char encoding")]
        return _match_helper(self.RULE_ID, p, request)
