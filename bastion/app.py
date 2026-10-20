"""
FastAPI Application Factory and Lifespan Orchestration for Bastion-TIP.
"""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx

from .logging_config import configure_logging
from .settings import Settings, get_settings

logger = logging.getLogger("bastion.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages startup and shutdown lifecycles:
    - Configures structured logging.
    - Initializes shared HTTPX client with connection pooling and explicit timeouts.
    - Ensures clean resource teardown on shutdown.
    """
    settings = getattr(app.state, "settings", get_settings())
    configure_logging(settings.bastion_log_level)
    logger.info("Starting Bastion WAF Gateway (env=%s, mode=%s)", settings.bastion_env, settings.bastion_default_mode)

    # Initialize shared async upstream client
    app.state.upstream_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.bastion_upstream_timeout_seconds, connect=5.0),
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=100, max_connections=200),
        verify=True,
    )
    app.state.ready = True
    yield
    logger.info("Shutting down Bastion WAF Gateway...")
    app.state.ready = False
    if hasattr(app.state, "upstream_client"):
        await app.state.upstream_client.aclose()
    logger.info("Bastion WAF Gateway shutdown complete.")


def create_app(settings: Settings | None = None) -> FastAPI:
    """FastAPI application factory."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="Bastion-TIP Gateway",
        description="Bastion Web Application Firewall + Threat Intelligence Platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.ready = False

    # Standard security headers & CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
        allow_headers=["*"],
    )

    # Health endpoints
    @app.get("/health/live", tags=["Health"])
    async def liveness():
        """Liveness check — returns 200 if process is active."""
        return {"status": "ok", "service": "bastion-gateway"}

    @app.get("/health/ready", tags=["Health"])
    async def readiness():
        """Readiness check — returns truthful status of components."""
        is_ready = getattr(app.state, "ready", False)
        status_code = 200 if is_ready else 503
        return {
            "status": "ready" if is_ready else "not_ready",
            "upstream_client": hasattr(app.state, "upstream_client"),
            "mode": settings.bastion_default_mode,
            "environment": settings.bastion_env,
        }

    return app
