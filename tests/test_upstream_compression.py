"""
Regression test for upstream compression (gzip, brotli, uncompressed)
and response header stripping in Bastion WAF reverse proxy.
"""

import gzip
import pytest
import brotli
import httpx
from starlette.requests import Request
from bastion.core.proxy import app, waf_proxy


async def _empty_receive():
    """Minimal ASGI receive that signals an empty request body."""
    return {"type": "http.request", "body": b"", "more_body": False}


def _make_request(path: str = "/", query_string: str = "") -> Request:
    """Build a Starlette Request with a proper receive channel."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string.encode(),
        "headers": [(b"host", b"127.0.0.1:8080"), (b"accept", b"text/html")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
        "app": app,
    }
    return Request(scope, receive=_empty_receive)


@pytest.mark.asyncio
async def test_upstream_gzip_response_decompressed_and_clean_headers(monkeypatch):
    """Verify that gzip compressed upstream response is decompressed and headers stripped."""
    raw_html = b"<!DOCTYPE html><html><body><h1>Portfolio</h1></body></html>"
    gzipped = gzip.compress(raw_html)

    async def mock_request(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "content-encoding": "gzip",
                "content-length": str(len(gzipped)),
                "server": "Netlify",
            },
            content=gzipped,
            request=httpx.Request("GET", "https://abrham-addis-portfolio.netlify.app/"),
        )

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    # app.state.client is initialised to None at module level; safe to overwrite here
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 200
        assert resp.body == raw_html
        assert "content-encoding" not in resp.headers
        assert "transfer-encoding" not in resp.headers
    finally:
        await mock_client.aclose()
        app.state.client = None


@pytest.mark.asyncio
async def test_upstream_brotli_response_decompressed_and_clean_headers(monkeypatch):
    """Verify that brotli compressed upstream response is decompressed and headers stripped."""
    raw_html = b"<!DOCTYPE html><html><body><h1>Brotli Content</h1></body></html>"
    compressed_br = brotli.compress(raw_html)

    async def mock_request(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "content-encoding": "br",
                "content-length": str(len(compressed_br)),
                "server": "Netlify",
            },
            content=compressed_br,
            request=httpx.Request("GET", "https://abrham-addis-portfolio.netlify.app/"),
        )

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 200
        assert resp.body == raw_html
        assert "content-encoding" not in resp.headers
    finally:
        await mock_client.aclose()
        app.state.client = None


@pytest.mark.asyncio
async def test_upstream_uncompressed_response(monkeypatch):
    """Verify that uncompressed responses pass through intact."""
    raw_html = b"<!DOCTYPE html><html><body>Plain Text</body></html>"

    async def mock_request(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            headers={
                "content-type": "text/html",
                "server": "Netlify",
            },
            content=raw_html,
            request=httpx.Request("GET", "https://abrham-addis-portfolio.netlify.app/"),
        )

    mock_client = httpx.AsyncClient()
    monkeypatch.setattr(mock_client, "request", mock_request)
    app.state.client = mock_client

    try:
        req = _make_request()
        resp = await waf_proxy(req, path="")
        assert resp.status_code == 200
        assert resp.body == raw_html
        assert "content-encoding" not in resp.headers
    finally:
        await mock_client.aclose()
        app.state.client = None
