"""
Regression test for upstream connection/DNS retry and failure recovery
in Bastion WAF reverse proxy.
"""

import pytest
import httpx
from starlette.requests import Request
from bastion.core.proxy import app, waf_proxy


async def _empty_receive():
    """Minimal ASGI receive that signals an empty request body."""
    return {"type": "http.request", "body": b"", "more_body": False}


def _make_request(path: str = "/") -> Request:
    """Build a Starlette Request with a proper receive channel."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8080"), (b"accept", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
        "app": app,
    }
    return Request(scope, receive=_empty_receive)


@pytest.mark.asyncio
async def test_upstream_dns_temporary_failure_recovers_on_retry(monkeypatch):
    """Test that a transient ConnectError (e.g. temporary DNS failure) recovers on retry."""
    attempts = 0

    async def mock_request(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution")
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/html"},
            content=b"<!DOCTYPE html><html><body>Recovered</body></html>",
            request=httpx.Request("GET", "https://abrham-addis-portfolio.netlify.app/"),
        )

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 200
        assert resp.body == b"<!DOCTYPE html><html><body>Recovered</body></html>"
        assert attempts == 2
    finally:
        await mock_client.aclose()
        app.state.client = None


@pytest.mark.asyncio
async def test_upstream_permanent_connect_failure_returns_502(monkeypatch):
    """Test that permanent ConnectError after max retries returns a 502 response."""
    attempts = 0

    async def mock_request(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("[Errno -3] Permanent failure in name resolution")

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 502
        assert attempts == 2
    finally:
        await mock_client.aclose()
        app.state.client = None


@pytest.mark.asyncio
async def test_upstream_timeout_returns_504(monkeypatch):
    """Test that an upstream timeout returns a 504 Gateway Timeout."""
    async def mock_request(*args, **kwargs):
        raise httpx.TimeoutException("Read timeout")

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 504
    finally:
        await mock_client.aclose()
        app.state.client = None
