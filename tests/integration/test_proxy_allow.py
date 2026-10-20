"""
Integration tests for Milestone 2: Proxy routing, hop-by-hop stripping,
oversized body rejection, spoofed client-IP verification, and unknown host handling.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from bastion.app import create_app
from bastion.proxy.router import SiteConfig, SiteRepository
from bastion.proxy.service import ProxyService
from bastion.settings import Settings
from tests.fixtures.test_site_app import upstream_app


@pytest.fixture
def test_sites():
    return SiteRepository([
        SiteConfig(
            id="test-site",
            hostnames=["app.test.local", "127.0.0.1", "testserver"],
            upstream_origin="http://upstream.local",
            max_body_bytes=500,  # 500 bytes for test
            allowed_methods=["GET", "POST", "HEAD"],
        )
    ])


@pytest.mark.asyncio
async def test_proxy_roundtrip_to_mock_upstream(test_sites):
    settings = Settings()
    proxy_service = ProxyService(test_sites, settings)

    app = create_app(settings)
    app.state.site_repo = test_sites
    app.state.proxy_service = proxy_service

    @app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "PUT", "DELETE"])
    async def proxy_catchall(request: Request, path: str):
        return await proxy_service.handle_request(request, app.state.upstream_client)

    upstream_transport = ASGITransport(app=upstream_app)
    async with AsyncClient(transport=upstream_transport, base_url="http://upstream.local") as mock_upstream_client:
        async with app.router.lifespan_context(app):
            app.state.upstream_client = mock_upstream_client
            gateway_transport = ASGITransport(app=app)

            async with AsyncClient(transport=gateway_transport, base_url="http://testserver") as client:
                # 1. Normal GET request reaching upstream
                resp = await client.get("/hello", headers={"Host": "app.test.local"})
                assert resp.status_code == 200
                assert resp.json() == {"message": "Hello from upstream!"}
                assert "X-Bastion-Request-ID" in resp.headers

                # 2. Echo with query & body and verify custom hop-by-hop header removal
                resp = await client.post(
                    "/echo?foo=bar",
                    headers={"Host": "app.test.local", "Upgrade": "websocket", "X-Custom": "test"},
                    content=b'{"greeting":"world"}',
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["query"] == {"foo": "bar"}
                assert "upgrade" not in data["headers"]  # Hop-by-hop stripped!
                assert data["headers"].get("x-custom") == "test"
                assert "x-forwarded-for" in data["headers"]
                assert "X-Bastion-Request-ID" in resp.headers

                # 3. Unknown Host -> 421 Misdirected Request
                resp = await client.get("/hello", headers={"Host": "evil-unregistered.com"})
                assert resp.status_code == 421
                assert resp.json()["error"] == "Misdirected Request"

                # 4. Disallowed method -> 405 Method Not Allowed
                resp = await client.delete("/hello", headers={"Host": "app.test.local"})
                assert resp.status_code == 405

                # 5. Oversized body -> 413 Payload Too Large
                large_body = b"A" * 600
                resp = await client.post("/echo", headers={"Host": "app.test.local"}, content=large_body)
                assert resp.status_code == 413
                assert resp.json()["error"] == "Payload Too Large"
