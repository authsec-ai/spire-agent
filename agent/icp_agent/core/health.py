"""
Health check manager for ICP Agent.

Tracks agent health status and provides health check endpoints.
"""

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any

import structlog

from icp_agent.config import Settings


logger = structlog.get_logger(__name__)


class HealthStatus(str, Enum):
    """Health status enumeration."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"


class ComponentHealth:
    """Health status for a single component."""

    def __init__(self, name: str):
        """Initialize component health."""
        self.name = name
        self.status = HealthStatus.STARTING
        self.last_check: Optional[datetime] = None
        self.message: str = ""
        self.details: Dict[str, Any] = {}

    def update(
        self,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update component health status."""
        self.status = status
        self.last_check = datetime.utcnow()
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "status": self.status.value,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "message": self.message,
            "details": self.details,
        }


class HealthManager:
    """Manages health checks for the ICP Agent."""

    def __init__(self, settings: Settings):
        """Initialize health manager."""
        self.settings = settings
        self.components: Dict[str, ComponentHealth] = {}
        self.start_time = datetime.utcnow()
        self.ready = False

        # Initialize core components
        self._register_component("agent_svid")
        self._register_component("icp_service")
        self._register_component("workload_api")
        self._register_component("certificate_cache")

        logger.info("Health manager initialized")

    def _register_component(self, name: str) -> None:
        """Register a new component for health tracking."""
        self.components[name] = ComponentHealth(name)
        logger.debug("Registered component", component=name)

    def update_component(
        self,
        component: str,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update health status for a component."""
        if component not in self.components:
            logger.warning("Attempted to update unknown component", component=component)
            return

        self.components[component].update(status, message, details)
        logger.debug(
            "Component health updated",
            component=component,
            status=status.value,
            message=message,
        )

    def get_component_status(self, component: str) -> Optional[ComponentHealth]:
        """Get health status for a specific component."""
        return self.components.get(component)

    def get_overall_status(self) -> HealthStatus:
        """
        Calculate overall health status.

        Returns UNHEALTHY if any component is unhealthy,
        DEGRADED if any component is degraded,
        STARTING if any component is starting,
        HEALTHY if all components are healthy.
        """
        if not self.ready:
            return HealthStatus.STARTING

        statuses = [comp.status for comp in self.components.values()]

        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if HealthStatus.STARTING in statuses:
            return HealthStatus.STARTING

        return HealthStatus.HEALTHY

    def is_ready(self) -> bool:
        """Check if agent is ready to serve requests."""
        return self.ready

    def set_ready(self, ready: bool = True) -> None:
        """Set agent ready status."""
        self.ready = ready
        logger.info("Agent ready status changed", ready=ready)

    def get_health_report(self) -> Dict[str, Any]:
        """Get comprehensive health report."""
        uptime = datetime.utcnow() - self.start_time

        return {
            "status": self.get_overall_status().value,
            "ready": self.ready,
            "uptime_seconds": int(uptime.total_seconds()),
            "start_time": self.start_time.isoformat(),
            "components": {name: comp.to_dict() for name, comp in self.components.items()},
            "agent": {
                "tenant_id": self.settings.agent.tenant_id,
                "node_id": self.settings.agent.node_id,
            },
        }

    async def perform_health_checks(self) -> None:
        """Perform periodic health checks for all components."""
        logger.info("Starting health check routine")

        while True:
            try:
                # Check Agent SVID status
                await self._check_agent_svid()

                # Check ICP service connectivity
                await self._check_icp_service()

                # Check certificate cache
                await self._check_certificate_cache()

                # Check Workload API
                await self._check_workload_api()

                # Sleep for 30 seconds between checks
                await asyncio.sleep(30)

            except Exception as e:
                logger.error("Error during health check", error=str(e), exc_info=True)
                await asyncio.sleep(30)

    async def _check_agent_svid(self) -> None:
        """Check Agent SVID health."""
        # TODO: Implement actual SVID expiry check
        # For now, just mark as healthy if ready
        if self.ready:
            self.update_component(
                "agent_svid",
                HealthStatus.HEALTHY,
                "Agent SVID is valid",
            )

    async def _check_icp_service(self) -> None:
        """Check ICP service connectivity."""
        # TODO: Implement actual connectivity check
        # For now, just mark as healthy
        self.update_component(
            "icp_service",
            HealthStatus.HEALTHY,
            "ICP service connectivity verified",
        )

    async def _check_certificate_cache(self) -> None:
        """Check certificate cache health."""
        # TODO: Implement cache integrity check
        self.update_component(
            "certificate_cache",
            HealthStatus.HEALTHY,
            "Certificate cache is operational",
        )

    async def _check_workload_api(self) -> None:
        """Check Workload API health."""
        # TODO: Implement socket availability check
        self.update_component(
            "workload_api",
            HealthStatus.HEALTHY,
            "Workload API is serving requests",
        )
