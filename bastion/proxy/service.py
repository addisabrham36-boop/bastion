"""
Proxy Service: Handles request routing, body limits, upstream request execution,
and streaming responses with X-Bastion-Request-ID.
"""

import uuid
from typing import AsyncIterator, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse, Response, StreamingResponse
import httpx

from .headers import (
    filter_upstream_request_headers,
    filter_upstream_response_headers,
    resolve_client_ip,
)
from .router import SiteConfig, SiteRepository
from ..settings import Settings


class ProxyService:
    def __init__(self, site_repository: SiteRepository, settings: Settings):
        self.sites = site_repository
        self.settings = settings

    async def handle_request(
        self,
        request: Request,
        client: httpx.AsyncClient,
    ) -> Response:
        request_id = str(uuid.uuid4())
        host = request.headers.get("host", "")
        peer_ip = request.client.host if request.client else "127.0.0.1"
        client_ip, ip_source = resolve_client_ip(
            peer_ip,
            dict(request.headers),
            self.settings.trusted_proxies_list,
        )

        # 1. Resolve Site
        site: Optional[SiteConfig] = self.sites.resolve_site(host)
        if not site:
            return JSONResponse(
                status_code=421,
                content={
                    "error": "Misdirected Request",
                    "message": f"Host '{host}' is not configured on this Bastion gateway.",
                    "request_id": request_id,
                },
                headers={"X-Bastion-Request-ID": request_id},
            )

        # 2. Check Allowed Methods
        if request.method not in site.allowed_methods:
            return JSONResponse(
                status_code=405,
                content={
                    "error": "Method Not Allowed",
                    "message": f"HTTP method '{request.method}' is not permitted for site '{site.id}'.",
                    "request_id": request_id,
                },
                headers={"X-Bastion-Request-ID": request_id},
            )

        # 3. Read Body with strict byte cap
        body_bytes = b""
        total_read = 0
        async for chunk in request.stream():
            total_read += len(chunk)
            if total_read > site.max_body_bytes:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Payload Too Large",
                        "message": f"Request body exceeded limit of {site.max_body_bytes} bytes.",
                        "request_id": request_id,
                    },
                    headers={"X-Bastion-Request-ID": request_id},
                )
            body_bytes += chunk

        # 4. Prepare Upstream Request
        upstream_url = f"{site.upstream_origin}{request.url.path}"
        if request.url.query:
            upstream_url = f"{upstream_url}?{request.url.query}"

        forward_headers = filter_upstream_request_headers(
            dict(request.headers),
            client_ip=client_ip,
            host=host,
        )

        # 5. Forward to configured upstream
        try:
            req = client.build_request(
                method=request.method,
                url=upstream_url,
                headers=forward_headers,
                content=body_bytes,
            )
            upstream_resp = await client.send(req, stream=True)

            resp_headers = filter_upstream_response_headers(dict(upstream_resp.headers))
            resp_headers["X-Bastion-Request-ID"] = request_id

            async def body_stream() -> AsyncIterator[bytes]:
                try:
                    async for chunk in upstream_resp.aiter_raw():
                        yield chunk
                finally:
                    await upstream_resp.aclose()

            return StreamingResponse(
                content=body_stream(),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
            )
        except httpx.ConnectTimeout:
            return JSONResponse(
                status_code=504,
                content={"error": "Gateway Timeout", "message": "Upstream connection timed out.", "request_id": request_id},
                headers={"X-Bastion-Request-ID": request_id},
            )
        except httpx.ReadTimeout:
            return JSONResponse(
                status_code=504,
                content={"error": "Gateway Timeout", "message": "Upstream read timed out.", "request_id": request_id},
                headers={"X-Bastion-Request-ID": request_id},
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=502,
                content={"error": "Bad Gateway", "message": f"Upstream communication error.", "request_id": request_id},
                headers={"X-Bastion-Request-ID": request_id},
            )
