"""
Policy for stripping hop-by-hop headers and safe handling of client forwarding headers.
"""

import ipaddress
from typing import Dict, List, Optional, Tuple

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def is_trusted_peer(peer_ip: str, trusted_cidrs: List[str]) -> bool:
    """Validate whether the immediate TCP/ASGI peer IP is inside a trusted proxy CIDR."""
    if not peer_ip:
        return False
    try:
        peer_addr = ipaddress.ip_address(peer_ip)
        for cidr in trusted_cidrs:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            if peer_addr in network:
                return True
    except ValueError:
        return False
    return False


def resolve_client_ip(
    peer_ip: str,
    headers: Dict[str, str],
    trusted_cidrs: List[str],
) -> Tuple[str, str]:
    """
    Determine the authentic client IP.
    Returns (client_ip, source_type).
    Only trusts X-Forwarded-For / Forwarded if peer_ip is in trusted_cidrs.
    """
    if not is_trusted_peer(peer_ip, trusted_cidrs):
        return peer_ip or "127.0.0.1", "peer"

    # Peer is a trusted reverse proxy (e.g. Caddy/Load Balancer). Inspect X-Forwarded-For.
    xff = headers.get("x-forwarded-for")
    if xff:
        # Client IP is the rightmost un-trusted or leftmost hop according to standard forwarding
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            candidate = parts[0]
            try:
                ipaddress.ip_address(candidate)
                return candidate, "trusted_proxy"
            except ValueError:
                pass

    return peer_ip or "127.0.0.1", "trusted_proxy"


def filter_upstream_request_headers(
    headers: Dict[str, str],
    client_ip: str,
    host: str,
) -> Dict[str, str]:
    """Clean headers before forwarding to upstream."""
    cleaned: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS:
            continue
        cleaned[k] = v

    # Inject safe forwarding headers
    cleaned["X-Forwarded-For"] = client_ip
    cleaned["X-Forwarded-Host"] = host
    cleaned["X-Forwarded-Proto"] = "http"
    return cleaned


def filter_upstream_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Clean headers returned by upstream before responding to client."""
    cleaned: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        cleaned[k] = v
    return cleaned
