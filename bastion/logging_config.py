"""
Safe structured logging with sensitive header/field redaction.
"""

import logging
import re
import sys
from typing import Any, Dict

SENSITIVE_PATTERNS = [
    re.compile(r"(authorization:\s*bearer\s+)[^\s]+", re.IGNORECASE),
    re.compile(r"(password[\"']?\s*[:=]\s*[\"'])[^\"']+", re.IGNORECASE),
    re.compile(r"(cookie:\s*)[^\r\n]+", re.IGNORECASE),
]


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            msg = pattern.sub(r"\1[REDACTED]", msg)
        return msg


def configure_logging(level: str = "INFO"):
    logger = logging.getLogger("bastion")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Avoid duplicate handlers on re-init
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
