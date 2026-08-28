"""
Extracts normalized parameters and structures from raw HTTP requests.
"""

from dataclasses import dataclass
from typing import Dict, Optional
from .normalizer import normalize_request, NormalizedRequest


@dataclass
class InspectionResult:
    request: NormalizedRequest


def inspect_request(
    method: str,
    path: str,
    query_string: str = "",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    client_ip: str = "",
) -> InspectionResult:
    normalized = normalize_request(
        method=method,
        path=path,
        query_string=query_string,
        headers=headers or {},
        body=body,
        client_ip=client_ip,
    )
    return InspectionResult(request=normalized)
