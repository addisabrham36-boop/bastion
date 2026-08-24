"""
Extracts the fields rules actually need from a raw HTTP request: query
params, headers, body (form/JSON/multipart), and path — decoupled from
proxy.py so this can be unit-tested without a live socket or real upstream.
Implemented in Phase 2, alongside proxy.py.
"""
from dataclasses import dataclass
from typing import Dict

from .normalizer import normalize_request, NormalizedRequest


@dataclass
class InspectionResult:
    request: NormalizedRequest


def inspect_request(
    method: str,
    path: str,
    query_string: str = "",
    headers: Dict[str, str] | None = None,
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
