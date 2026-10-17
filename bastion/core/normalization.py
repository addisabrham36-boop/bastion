"""
Content-type aware bounded normalization for inspection.
Ensures WAF inspection views never corrupt or rewrite forwarded traffic.
"""

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus


def repeated_url_decode(value: str, max_iterations: int = 5) -> str:
    """Repeated URL decode until fixed point or max iterations reached."""
    current = value
    for _ in range(max_iterations):
        nxt = unquote_plus(current)
        if nxt == current:
            break
        current = nxt
    return current


def canonicalize_path(raw_path: str) -> str:
    """Canonicalize path: repeated decode, handle backslashes, collapse repeated slashes."""
    decoded = repeated_url_decode(raw_path)
    decoded = decoded.replace("\\", "/")
    # Collapse multiple slashes
    parts = [p for p in decoded.split("/") if p and p != "."]
    # Process dot segments safely
    resolved: List[str] = []
    for part in parts:
        if part == "..":
            if resolved:
                resolved.pop()
        else:
            resolved.append(part)
    return "/" + "/".join(resolved)


def parse_bounded_query(raw_query: str, max_params: int = 100) -> Dict[str, List[str]]:
    """Parse query string while preserving duplicate parameters up to max_params."""
    if not raw_query:
        return {}
    res: Dict[str, List[str]] = {}
    count = 0
    for pair in raw_query.split("&"):
        if not pair:
            continue
        count += 1
        if count > max_params:
            break
        key, _, val = pair.partition("=")
        clean_key = repeated_url_decode(key)
        clean_val = repeated_url_decode(val)
        res.setdefault(clean_key, []).append(clean_val)
    return res


def parse_bounded_form(body_bytes: bytes, max_params: int = 100) -> Dict[str, List[str]]:
    """Parse application/x-www-form-urlencoded body."""
    try:
        text = body_bytes.decode("utf-8", errors="replace")
        return parse_bounded_query(text, max_params=max_params)
    except Exception:
        return {}


def parse_bounded_json(body_bytes: bytes, max_bytes: int = 1_048_576, max_depth: int = 10) -> Optional[Any]:
    """Parse JSON body with size and recursion depth limits."""
    if not body_bytes or len(body_bytes) > max_bytes:
        return None
    try:
        data = json.loads(body_bytes.decode("utf-8", errors="replace"))

        def check_depth(obj, depth=0):
            if depth > max_depth:
                raise ValueError("JSON nesting depth exceeded")
            if isinstance(obj, dict):
                for v in obj.values():
                    check_depth(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, depth + 1)

        check_depth(data)
        return data
    except Exception:
        return None
