"""
Java injection detection rules (OWASP CRS 944xxx).

Covers:
- 944100  JavaELInjectionRule      – Java EL / OGNL injection
- 944110  Log4ShellRule            – Log4Shell (CVE-2021-44228) and variants
- 944200  JavaDeserializationRule  – Java deserialization attack payloads
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 944100 – Java EL / OGNL injection
# ---------------------------------------------------------------------------

_JAVA_EL_PATTERNS: List[Tuple[str, str]] = [
    (r"\$\{.*?\}", "Java EL expression (${...})"),
    (r"#\{.*?\}", "Java EL alternative expression (#{...})"),
    (r"%24%7B", "URL-encoded Java EL expression (%24%7B = ${)"),
    (r"\bognl\.", "OGNL expression injection"),
    (r"\bRuntime\.getRuntime\b", "Java Runtime.getRuntime() – RCE attempt"),
    (r"\bProcessBuilder\b", "Java ProcessBuilder – RCE attempt"),
    (r"\bRuntime\.exec\b", "Java Runtime.exec() – RCE attempt"),
    (r"\bClass\.forName\b", "Java Class.forName() – reflection abuse"),
    (r"\bThread\.sleep\b", "Java Thread.sleep() – blind injection probe"),
]
_COMPILED_JAVA_EL = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _JAVA_EL_PATTERNS
]

# ---------------------------------------------------------------------------
# 944110 – Log4Shell (CVE-2021-44228) and related variants
# ---------------------------------------------------------------------------

_LOG4SHELL_PATTERNS: List[Tuple[str, str]] = [
    (r"\$\{jndi:", "Log4Shell JNDI injection (${jndi:...})"),
    (r"\$\{jndi:ldap://", "Log4Shell JNDI LDAP lookup"),
    (r"\$\{jndi:rmi://", "Log4Shell JNDI RMI lookup"),
    (r"\$\{jndi:dns://", "Log4Shell JNDI DNS lookup"),
    (r"\$\{jndi:ldaps://", "Log4Shell JNDI LDAPS lookup"),
    (r"\$\{jndi:iiop://", "Log4Shell JNDI IIOP lookup"),
    (r"\$\{jndi:corba://", "Log4Shell JNDI CORBA lookup"),
    (r"\$\{jndi:nis://", "Log4Shell JNDI NIS lookup"),
    # Obfuscation variants
    (r"\$\{\$\{", "Log4Shell nested expression obfuscation"),
    (r"\$\{lower:", "Log4Shell lower: obfuscation"),
    (r"\$\{upper:", "Log4Shell upper: obfuscation"),
    (r"\$\{::-j\}", "Log4Shell empty-prefix obfuscation (::-j)"),
    (r"\$\{env:NaN:-j\}", "Log4Shell env:NaN obfuscation"),
]
_COMPILED_LOG4SHELL = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _LOG4SHELL_PATTERNS
]

# ---------------------------------------------------------------------------
# 944200 – Java deserialization
# ---------------------------------------------------------------------------

_JAVA_DESER_PATTERNS: List[Tuple[str, str]] = [
    (r"rO0AB", "Base64-encoded Java serialized object header (rO0AB)"),
    (r"\\xac\\xed\\x00\\x05", "Java serialization magic bytes (0xACED0005)"),
    (r"org\.apache\.commons\.collections", "Apache Commons Collections gadget chain"),
    (r"java\.rmi\.", "Java RMI class reference – deserialization gadget"),
    (r"\bweblogic\b", "WebLogic deserialization gadget reference"),
    (r"com\.sun\.org\.apache\.xalan", "Xalan XSLT gadget chain reference"),
    (r"\bysoserial\b", "ysoserial payload tool reference"),
    (r"\bCommonsCollections\b", "CommonsCollections gadget chain reference"),
]
_COMPILED_JAVA_DESER = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _JAVA_DESER_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class JavaELInjectionRule(Rule):
    """Detect Java EL / OGNL injection (OWASP CRS 944100)."""

    RULE_ID = "944100"
    NAME = "Java EL / OGNL Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_JAVA_EL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class Log4ShellRule(Rule):
    """Detect Log4Shell (CVE-2021-44228) and obfuscated variants (OWASP CRS 944110)."""

    RULE_ID = "944110"
    NAME = "Log4Shell / Log4j JNDI Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_LOG4SHELL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class JavaDeserializationRule(Rule):
    """Detect Java deserialization attack payloads (OWASP CRS 944200)."""

    RULE_ID = "944200"
    NAME = "Java Deserialization Attack Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_JAVA_DESER:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
