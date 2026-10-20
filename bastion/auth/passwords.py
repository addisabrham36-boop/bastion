"""
Secure password hashing and token generation using standard hashlib PBKDF2-HMAC-SHA256.
No external native C-dependencies required.
"""

import hashlib
import hmac
import os
import secrets
from typing import Tuple


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Generate PBKDF2-HMAC-SHA256 password hash."""
    if salt is None:
        salt = os.urandom(16)
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, hash_str: str) -> bool:
    """Safely verify password against stored PBKDF2 hash using constant-time comparison."""
    try:
        header, salt_hex, derived_hex = hash_str.split("$")
        parts = header.split(":")
        iterations = int(parts[2])
        salt = bytes.fromhex(salt_hex)
        expected_derived = bytes.fromhex(derived_hex)

        actual_derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual_derived, expected_derived)
    except Exception:
        return False


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)
