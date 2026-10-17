"""
High-precision, bounded defensive payload rules (SQLi, XSS, Path Traversal, Command Injection).
Includes safe regex boundaries and false-positive protections.
"""

import re
from typing import Optional
from ..base import BaseRule
from ...core.context import Detection, EvaluationState, RequestContext
from ...core.enums import RuleCategory, Severity


class SQLiUnionSelectRule(BaseRule):
    id = "PAYLOAD_SQLI_001"
    name = "SQL Injection UNION SELECT Indicator"
    category = RuleCategory.PAYLOAD
    severity = Severity.HIGH
    confidence = 0.85
    score = 40
    enabled = True
    tags = ["sqli", "injection"]
    description = "Detects classic UNION SELECT injection indicators."
    pattern = re.compile(r"(?i)\bunion\s+(all\s+)?select\b")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        # Check query, form, text body
        targets = [context.raw_query, context.text_body]
        for val_list in context.query_params.values():
            targets.extend(val_list)
        for val_list in context.form_params.values():
            targets.extend(val_list)

        for text in targets:
            if not text:
                continue
            m = self.pattern.search(text)
            if m:
                return Detection(
                    rule_id=self.id,
                    category=self.category.value,
                    severity=self.severity.value,
                    confidence=self.confidence,
                    score=self.score,
                    message="Detected SQL Injection UNION SELECT signature.",
                    location="payload",
                    evidence=m.group(0),
                )
        return None


class XSSScriptTagRule(BaseRule):
    id = "PAYLOAD_XSS_001"
    name = "Cross-Site Scripting Script/Event Indicator"
    category = RuleCategory.PAYLOAD
    severity = Severity.HIGH
    confidence = 0.85
    score = 40
    enabled = True
    tags = ["xss"]
    description = "Detects executable script tags and inline event handlers in input fields."
    pattern = re.compile(r"(?i)(<script\b[^>]*>|javascript:\s*|\bonerror\s*=|\bonload\s*=)")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        targets = [context.raw_query, context.text_body, context.canonical_path]
        for val_list in context.query_params.values():
            targets.extend(val_list)
        for val_list in context.form_params.values():
            targets.extend(val_list)

        for text in targets:
            if not text:
                continue
            m = self.pattern.search(text)
            if m:
                return Detection(
                    rule_id=self.id,
                    category=self.category.value,
                    severity=self.severity.value,
                    confidence=self.confidence,
                    score=self.score,
                    message="Detected XSS script or event handler indicator.",
                    location="payload",
                    evidence=m.group(0),
                )
        return None


class PathTraversalDotDotRule(BaseRule):
    id = "PAYLOAD_TRAVERSAL_001"
    name = "Path Traversal Directory Escape Indicator"
    category = RuleCategory.PAYLOAD
    severity = Severity.HIGH
    confidence = 0.90
    score = 40
    enabled = True
    tags = ["traversal", "lfi"]
    description = "Detects path traversal sequences traversing above root."
    pattern = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self/|c:\\windows)")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        targets = [context.raw_path, context.canonical_path, context.raw_query, context.text_body]
        for val_list in context.query_params.values():
            targets.extend(val_list)

        for text in targets:
            if not text:
                continue
            m = self.pattern.search(text.lower())
            if m:
                return Detection(
                    rule_id=self.id,
                    category=self.category.value,
                    severity=self.severity.value,
                    confidence=self.confidence,
                    score=self.score,
                    message="Detected path traversal or sensitive file escape sequence.",
                    location="path/query",
                    evidence=m.group(0),
                )
        return None


class CommandInjectionChainingRule(BaseRule):
    id = "PAYLOAD_CMDI_001"
    name = "Command Injection Chaining Indicator"
    category = RuleCategory.PAYLOAD
    severity = Severity.CRITICAL
    confidence = 0.85
    score = 50
    enabled = True
    tags = ["rce", "cmdi"]
    description = "Detects shell command chaining tokens with typical unix/windows utilities."
    pattern = re.compile(r"(?i)(;\s*(whoami|id|uname|cat\s+/etc/passwd|nc\s+-e|bash\s+-i|cmd\.exe)|\b\|\s*(whoami|id|cat)\b)")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        targets = [context.raw_query, context.text_body]
        for val_list in context.query_params.values():
            targets.extend(val_list)
        for val_list in context.form_params.values():
            targets.extend(val_list)

        for text in targets:
            if not text:
                continue
            m = self.pattern.search(text)
            if m:
                return Detection(
                    rule_id=self.id,
                    category=self.category.value,
                    severity=self.severity.value,
                    confidence=self.confidence,
                    score=self.score,
                    message="Detected OS command execution chaining indicator.",
                    location="payload",
                    evidence=m.group(0),
                )
        return None
