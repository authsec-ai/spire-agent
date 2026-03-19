"""
FastAPI application for ICP Agent.

Provides HTTP health check and status endpoints.
The Workload API is served via Unix socket separately.
"""

from typing import Dict, Any

import structlog
from fastapi import FastAPI, Response, status
from fastapi.responses import JSONResponse

from icp_agent.config import Settings
from icp_agent.core.health import HealthManager, HealthStatus


logger = structlog.get_logger(__name__)


def create_app(settings: Settings, health_manager: HealthManager) -> FastAPI:
    """
    Create FastAPI application.

    Args:
        settings: Application settings
        health_manager: Health manager instance

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="ICP Agent",
        description="SPIRE Agent replacement for multi-tenant M2M authentication",
        version="0.1.0",
        docs_url=None,  # Disable docs in production
        redoc_url=None,  # Disable redoc in production
    )

    @app.get("/health", tags=["Health"])
    async def health_check() -> JSONResponse:
        """
        Health check endpoint.

        Returns basic health status without detailed information.
        Used by orchestrators (K8s liveness probe).
        """
        overall_status = health_manager.get_overall_status()

        if overall_status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED):
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": overall_status.value},
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": overall_status.value},
            )

    @app.get("/ready", tags=["Health"])
    async def readiness_check() -> JSONResponse:
        """
        Readiness check endpoint.

        Returns ready status. Used by orchestrators (K8s readiness probe).
        """
        if health_manager.is_ready():
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"ready": True},
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"ready": False},
            )

    @app.get("/status", tags=["Status"])
    async def status_endpoint() -> Dict[str, Any]:
        """
        Detailed status endpoint.

        Returns comprehensive health report including all components.
        """
        return health_manager.get_health_report()

    @app.get("/", tags=["Info"])
    async def root() -> Dict[str, str]:
        """Root endpoint with basic info."""
        return {
            "service": "ICP Agent",
            "version": "0.1.0",
            "tenant_id": settings.agent.tenant_id,
            "node_id": settings.agent.node_id,
        }

    logger.info("FastAPI application created")

    return app
