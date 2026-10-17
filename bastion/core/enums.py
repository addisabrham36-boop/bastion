"""
Typed enums for WAF modes, actions, rule severities, and locations.
"""

from enum import Enum


class Mode(str, Enum):
    DETECTION = "detection"
    PREVENTION = "prevention"


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(str, Enum):
    PROTOCOL = "protocol"
    PAYLOAD = "payload"
    NETWORK = "network"
    BEHAVIORAL = "behavioral"
