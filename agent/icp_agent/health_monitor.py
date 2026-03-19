"""
Health Monitoring and Telemetry

Provides comprehensive health monitoring and telemetry using structured logging.
No Prometheus required - all metrics available via logs.

Epic 9 - SPIRE-80, SPIRE-81
"""

import asyncio
import logging
import json
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status for a component"""
    name: str
    status: HealthStatus
    message: str
    last_check: datetime
    details: Dict[str, Any]


@dataclass
class SystemMetrics:
    """System-level metrics"""
    timestamp: datetime
    uptime_seconds: int
    total_workloads: int
    active_svids: int
    total_issued: int
    total_rotated: int
    rotation_failures: int
    avg_rotation_time_ms: float
    workload_entries_cached: int
    api_requests_total: int
    api_errors_total: int


class HealthMonitor:
    """
    Monitors agent health and logs structured telemetry data

    Instead of Prometheus, uses JSON-formatted log entries that can be:
    - Parsed by log aggregators (ELK, Splunk, etc.)
    - Queried with jq/grep
    - Visualized with log dashboards
    """

    def __init__(
        self,
        workload_manager,
        cert_lifecycle,
        workload_api_server,
        check_interval: int = 60,  # Health check every 60 seconds
        metrics_interval: int = 30,  # Log metrics every 30 seconds
        logger: Optional[logging.Logger] = None
    ):
        self.workload_manager = workload_manager
        self.cert_lifecycle = cert_lifecycle
        self.workload_api_server = workload_api_server
        self.check_interval = check_interval
        self.metrics_interval = metrics_interval
        self.logger = logger or logging.getLogger(__name__)

        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {}

        # Metrics tracking
        self.start_time = time.time()
        self.api_requests = 0
        self.api_errors = 0

        # Background tasks
        self.health_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self.running = False

    async def start(self):
        """Start health monitoring"""
        self.logger.info("Starting Health Monitor")
        self.logger.info(f"  Health Check Interval: {self.check_interval}s")
        self.logger.info(f"  Metrics Log Interval: {self.metrics_interval}s")

        self.running = True
        self.start_time = time.time()

        # Start background tasks
        self.health_task = asyncio.create_task(self._health_check_loop())
        self.metrics_task = asyncio.create_task(self._metrics_loop())

        self.logger.info("✓ Health Monitor started")

        # Log initial health check
        await self._check_health()

    async def stop(self):
        """Stop health monitoring"""
        self.logger.info("Stopping Health Monitor")
        self.running = False

        if self.health_task:
            self.health_task.cancel()
            try:
                await self.health_task
            except asyncio.CancelledError:
                pass

        if self.metrics_task:
            self.metrics_task.cancel()
            try:
                await self.metrics_task
            except asyncio.CancelledError:
                pass

        self.logger.info("✓ Health Monitor stopped")

    async def _health_check_loop(self):
        """Background task for periodic health checks"""
        while self.running:
            try:
                await asyncio.sleep(self.check_interval)

                if not self.running:
                    break

                await self._check_health()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")

    async def _metrics_loop(self):
        """Background task for periodic metrics logging"""
        while self.running:
            try:
                await asyncio.sleep(self.metrics_interval)

                if not self.running:
                    break

                self._log_metrics()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in metrics loop: {e}")

    async def _check_health(self):
        """Perform comprehensive health check"""
        overall_status = HealthStatus.HEALTHY

        # Check Workload Manager
        wm_health = self._check_workload_manager()
        self.component_health["workload_manager"] = wm_health
        if wm_health.status != HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED

        # Check Certificate Lifecycle
        cl_health = self._check_certificate_lifecycle()
        self.component_health["certificate_lifecycle"] = cl_health
        if cl_health.status != HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED

        # Check Workload API
        api_health = self._check_workload_api()
        self.component_health["workload_api"] = api_health
        if api_health.status != HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED

        # Log structured health status
        self._log_health_status(overall_status)

    def _check_workload_manager(self) -> ComponentHealth:
        """Check Workload Manager health"""
        try:
            entries_count = len(self.workload_manager.workload_entries)
            svids_count = len(self.workload_manager.workload_svids)

            # Check if entries are stale
            last_updated = self.workload_manager.entries_last_updated
            is_stale = False
            if last_updated:
                # Use naive UTC for consistent timezone handling
                # Strip timezone info if present to ensure naive datetime comparison
                if last_updated.tzinfo is not None:
                    last_updated = last_updated.replace(tzinfo=None)
                # Use naive UTC datetime for comparison to avoid deprecation warning
                now_utc = datetime.now().replace(tzinfo=None) if datetime.now().tzinfo else datetime.now()
                age = (now_utc - last_updated).total_seconds()
                is_stale = age > 600  # 10 minutes

            if is_stale:
                status = HealthStatus.DEGRADED
                message = "Workload entries are stale"
            elif entries_count == 0:
                status = HealthStatus.DEGRADED
                message = "No workload entries cached"
            else:
                status = HealthStatus.HEALTHY
                message = f"{entries_count} entries, {svids_count} active SVIDs"

            return ComponentHealth(
                name="workload_manager",
                status=status,
                message=message,
                last_check=datetime.now(),
                details={
                    "workload_entries": entries_count,
                    "active_svids": svids_count,
                    "last_updated": last_updated.isoformat() if last_updated else None,
                    "entries_stale": is_stale
                }
            )

        except Exception as e:
            return ComponentHealth(
                name="workload_manager",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking health: {e}",
                last_check=datetime.now(),
                details={}
            )

    def _check_certificate_lifecycle(self) -> ComponentHealth:
        """Check Certificate Lifecycle health"""
        try:
            metrics = self.cert_lifecycle.get_metrics()

            # Check rotation failure rate
            failure_rate = 0.0
            if metrics.total_rotated > 0:
                failure_rate = metrics.rotation_failures / (metrics.total_rotated + metrics.rotation_failures)

            if failure_rate > 0.2:  # >20% failure rate
                status = HealthStatus.DEGRADED
                message = f"High rotation failure rate: {failure_rate*100:.1f}%"
            elif metrics.rotation_failures > 0:
                status = HealthStatus.DEGRADED
                message = f"{metrics.rotation_failures} rotation failures"
            else:
                status = HealthStatus.HEALTHY
                message = f"{metrics.active_certificates} active certificates"

            return ComponentHealth(
                name="certificate_lifecycle",
                status=status,
                message=message,
                last_check=datetime.now(),
                details={
                    "active_certificates": metrics.active_certificates,
                    "total_issued": metrics.total_issued,
                    "total_rotated": metrics.total_rotated,
                    "rotation_failures": metrics.rotation_failures,
                    "avg_rotation_time_ms": metrics.average_rotation_time_ms,
                    "failure_rate": failure_rate
                }
            )

        except Exception as e:
            return ComponentHealth(
                name="certificate_lifecycle",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking health: {e}",
                last_check=datetime.now(),
                details={}
            )

    def _check_workload_api(self) -> ComponentHealth:
        """Check Workload API health"""
        try:
            # Check if server is running
            if hasattr(self.workload_api_server, 'server') and self.workload_api_server.server:
                status = HealthStatus.HEALTHY
                message = "gRPC server running"

                # Count active streams if available
                active_streams = 0
                if hasattr(self.workload_api_server, 'servicer'):
                    servicer = self.workload_api_server.servicer
                    if hasattr(servicer, 'x509_subscribers'):
                        active_streams = len(servicer.x509_subscribers)

                details = {
                    "active_streams": active_streams,
                    "socket_path": self.workload_api_server.socket_path
                }
            else:
                status = HealthStatus.UNHEALTHY
                message = "gRPC server not running"
                details = {}

            return ComponentHealth(
                name="workload_api",
                status=status,
                message=message,
                last_check=datetime.now(),
                details=details
            )

        except Exception as e:
            return ComponentHealth(
                name="workload_api",
                status=HealthStatus.UNHEALTHY,
                message=f"Error checking health: {e}",
                last_check=datetime.now(),
                details={}
            )

    def _log_health_status(self, overall_status: HealthStatus):
        """Log structured health status"""
        health_data = {
            "type": "health_check",
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status.value,
            "components": {
                name: {
                    "status": health.status.value,
                    "message": health.message,
                    "last_check": health.last_check.isoformat(),
                    "details": health.details
                }
                for name, health in self.component_health.items()
            }
        }

        # Log as structured JSON
        if overall_status == HealthStatus.HEALTHY:
            self.logger.info(f"HEALTH_CHECK: {json.dumps(health_data)}")
        elif overall_status == HealthStatus.DEGRADED:
            self.logger.warning(f"HEALTH_CHECK: {json.dumps(health_data)}")
        else:
            self.logger.error(f"HEALTH_CHECK: {json.dumps(health_data)}")

    def _log_metrics(self):
        """Log structured metrics"""
        uptime = int(time.time() - self.start_time)

        # Gather metrics from all components
        cert_metrics = self.cert_lifecycle.get_metrics()

        metrics = SystemMetrics(
            timestamp=datetime.now(),
            uptime_seconds=uptime,
            total_workloads=len(self.workload_manager.tracked_pids),
            active_svids=len(self.workload_manager.workload_svids),
            total_issued=cert_metrics.total_issued,
            total_rotated=cert_metrics.total_rotated,
            rotation_failures=cert_metrics.rotation_failures,
            avg_rotation_time_ms=cert_metrics.average_rotation_time_ms,
            workload_entries_cached=len(self.workload_manager.workload_entries),
            api_requests_total=self.api_requests,
            api_errors_total=self.api_errors
        )

        # Log as structured JSON
        metrics_data = {
            "type": "metrics",
            **asdict(metrics)
        }
        metrics_data['timestamp'] = metrics_data['timestamp'].isoformat()

        self.logger.info(f"METRICS: {json.dumps(metrics_data)}")

    def record_api_request(self, success: bool = True):
        """Record an API request"""
        self.api_requests += 1
        if not success:
            self.api_errors += 1

    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        overall_healthy = all(
            h.status == HealthStatus.HEALTHY
            for h in self.component_health.values()
        )

        return {
            "overall_status": "healthy" if overall_healthy else "degraded",
            "components": {
                name: {
                    "status": health.status.value,
                    "message": health.message,
                    "last_check": health.last_check.isoformat()
                }
                for name, health in self.component_health.items()
            },
            "uptime_seconds": int(time.time() - self.start_time)
        }


class LogDashboard:
    """
    Helper class to format logs for easy viewing
    Provides methods to parse and display structured logs
    """

    @staticmethod
    def parse_log_line(line: str) -> Optional[Dict]:
        """Parse a structured log line"""
        try:
            # Extract JSON after HEALTH_CHECK: or METRICS:
            if "HEALTH_CHECK:" in line:
                json_str = line.split("HEALTH_CHECK:")[1].strip()
                return json.loads(json_str)
            elif "METRICS:" in line:
                json_str = line.split("METRICS:")[1].strip()
                return json.loads(json_str)
            return None
        except Exception:
            return None

    @staticmethod
    def format_health_check(data: Dict) -> str:
        """Format health check data for display"""
        output = []
        output.append("=" * 60)
        output.append(f"Health Check - {data['timestamp']}")
        output.append(f"Overall Status: {data['overall_status'].upper()}")
        output.append("=" * 60)

        for comp_name, comp_data in data['components'].items():
            status_symbol = "✓" if comp_data['status'] == "healthy" else "✗"
            output.append(f"\n{status_symbol} {comp_name.replace('_', ' ').title()}")
            output.append(f"  Status: {comp_data['status']}")
            output.append(f"  Message: {comp_data['message']}")

            if 'details' in comp_data and comp_data['details']:
                output.append("  Details:")
                for key, value in comp_data['details'].items():
                    output.append(f"    {key}: {value}")

        return "\n".join(output)

    @staticmethod
    def format_metrics(data: Dict) -> str:
        """Format metrics data for display"""
        output = []
        output.append("=" * 60)
        output.append(f"System Metrics - {data['timestamp']}")
        output.append("=" * 60)

        output.append(f"\nUptime: {data['uptime_seconds']}s ({data['uptime_seconds']//60}m)")
        output.append(f"\nWorkloads:")
        output.append(f"  Total Tracked: {data['total_workloads']}")
        output.append(f"  Active SVIDs: {data['active_svids']}")
        output.append(f"  Cached Entries: {data['workload_entries_cached']}")

        output.append(f"\nCertificates:")
        output.append(f"  Total Issued: {data['total_issued']}")
        output.append(f"  Total Rotated: {data['total_rotated']}")
        output.append(f"  Rotation Failures: {data['rotation_failures']}")
        output.append(f"  Avg Rotation Time: {data['avg_rotation_time_ms']:.2f}ms")

        output.append(f"\nAPI:")
        output.append(f"  Total Requests: {data['api_requests_total']}")
        output.append(f"  Errors: {data['api_errors_total']}")

        return "\n".join(output)
