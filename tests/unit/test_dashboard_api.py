"""
Unit tests for Milestone 8: Secure Dashboard API, role authorization, and audit trail.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from bastion.api.routes.control import router as control_router
from bastion.auth.passwords import hash_password, verify_password


def test_password_hashing():
    pw = "SuperSecretPassword123!"
    pw_hash = hash_password(pw)
    assert pw_hash.startswith("pbkdf2:sha256:")
    assert verify_password(pw, pw_hash) is True
    assert verify_password("WrongPassword", pw_hash) is False


@pytest.mark.asyncio
async def test_control_api_auth_and_roles():
    app = FastAPI()
    app.include_router(control_router)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Anonymous access denied on overview
        resp = await client.get("/api/v1/overview")
        assert resp.status_code == 401

        # 2. Viewer token can access overview
        resp = await client.get("/api/v1/overview", headers={"Authorization": "Bearer dev-viewer-token"})
        assert resp.status_code == 200
        assert resp.json()["total_requests"] >= 0

        # 3. Viewer token cannot perform admin mutations
        resp = await client.post(
            "/api/v1/sites/demo/mode",
            headers={"Authorization": "Bearer dev-viewer-token"},
            json={"mode": "prevention"},
        )
        assert resp.status_code == 403

        # 4. Admin token can perform mutations and records audit log
        resp = await client.post(
            "/api/v1/sites/demo/mode",
            headers={"Authorization": "Bearer dev-admin-token"},
            json={"mode": "prevention"},
        )
        assert resp.status_code == 200
        assert resp.json()["mode"] == "prevention"

        # Check audit trail
        resp = await client.get("/api/v1/audit", headers={"Authorization": "Bearer dev-admin-token"})
        assert resp.status_code == 200
        entries = resp.json()
        assert any(e.get("action") == "SET_MODE" for e in entries)
