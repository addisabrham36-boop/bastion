"""
Unit tests for Milestone 1: App factory, settings, lifecycle, and health endpoints.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from bastion.app import create_app
from bastion.settings import Settings, get_settings, reset_settings


def test_settings_validation_and_defaults():
    reset_settings()
    settings = get_settings()
    assert settings.bastion_env == "development"
    assert settings.bastion_default_mode == "detection"
    assert settings.bastion_max_body_bytes == 1_048_576
    assert "127.0.0.1/32" in settings.trusted_proxies_list

    # Validate mode constraint
    with pytest.raises(ValueError):
        Settings(BASTION_DEFAULT_MODE="invalid_mode")


@pytest.mark.asyncio
async def test_app_lifecycle_and_health_endpoints():
    app = create_app()
    # Using LifespanManager or entering lifespan context directly
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Liveness check
            resp = await client.get("/health/live")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

            # Readiness check
            resp = await client.get("/health/ready")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ready"
            assert data["upstream_client"] is True
            assert data["mode"] == "detection"
