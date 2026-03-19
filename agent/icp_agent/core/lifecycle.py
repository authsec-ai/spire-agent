"""
Agent lifecycle manager.

Handles agent startup, shutdown, and initialization sequence.
"""

import asyncio
import signal
from typing import Optional, Any

import structlog

from icp_agent.cache import CertificateCache, CachedSVID
from icp_agent.client import ICPClient
from icp_agent.config import Settings
from icp_agent.core.health import HealthManager, HealthStatus
from icp_agent.core.node_attestation import NodeAttestationManager
from icp_agent.grpc_workload_api import GRPCWorkloadAPIServer
from icp_agent.workload_manager import WorkloadManager
from icp_agent.log_config import setup_logging


logger = structlog.get_logger(__name__)


class AgentLifecycle:
    """Manages the lifecycle of the ICP Agent."""

    def __init__(self, settings: Settings):
        """Initialize agent lifecycle manager."""
        self.settings = settings
        self.health_manager = HealthManager(settings)
        self.shutdown_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []

        # Initialize components
        self.cert_cache: Optional[CertificateCache] = None
        self.icp_client: Optional[ICPClient] = None
        self.node_attest_manager: Optional[NodeAttestationManager] = None
        self.current_agent_svid: Optional[CachedSVID] = None
        self.workload_manager: Optional[WorkloadManager] = None
        self.grpc_workload_server: Optional[GRPCWorkloadAPIServer] = None

        logger.info(
            "Agent lifecycle initialized",
            tenant_id=settings.agent.tenant_id,
            node_id=settings.agent.node_id,
        )

    async def startup(self) -> None:
        """
        Perform agent startup sequence.

        1. Validate configuration
        2. Ensure required directories exist
        3. Initialize certificate cache
        4. Perform node attestation (if no valid Agent SVID)
        5. Start background tasks
        """
        logger.info("Starting agent initialization")

        try:
            # Step 1: Validate configuration
            logger.info("Validating configuration")
            self.settings.validate_required()
            logger.info("Configuration validated successfully")

            # Step 2: Ensure directories exist
            logger.info("Creating required directories")
            self.settings.ensure_directories()
            logger.info("Directories created successfully")

            # Step 3: Initialize certificate cache
            logger.info("Initializing certificate cache")
            self.cert_cache = CertificateCache(
                cache_path=self.settings.security.cache_path,
                encryption_key=self.settings.security.cache_encryption_key or None,
            )
            self.health_manager.update_component(
                "certificate_cache",
                HealthStatus.HEALTHY,
                "Certificate cache initialized",
            )

            # Step 4: Initialize ICP service client
            logger.info("Initializing ICP service client")
            self.icp_client = ICPClient(self.settings)

            # Step 5: Initialize node attestation manager
            logger.info("Initializing node attestation manager")
            self.node_attest_manager = NodeAttestationManager(
                self.settings,
                self.icp_client,
                self.cert_cache,
            )
            await self.node_attest_manager.initialize()

            # Step 6: Check for existing Agent SVID
            logger.info("Checking for existing Agent SVID")
            has_valid_svid = await self._check_agent_svid()

            if not has_valid_svid:
                logger.info("No valid Agent SVID found, performing node attestation")
                try:
                    self.current_agent_svid = await self.node_attest_manager.perform_node_attestation()
                    self.health_manager.update_component(
                        "agent_svid",
                        HealthStatus.HEALTHY,
                        "Agent SVID obtained via node attestation",
                        details={
                            "spiffe_id": self.current_agent_svid.spiffe_id,
                            "expiry": self.current_agent_svid.expiry.isoformat(),
                        },
                    )
                except Exception as e:
                    logger.error("Node attestation failed", error=str(e), exc_info=True)
                    self.health_manager.update_component(
                        "agent_svid",
                        HealthStatus.UNHEALTHY,
                        f"Node attestation failed: {str(e)}",
                    )
                    raise
            else:
                logger.info("Valid Agent SVID found")
                self.health_manager.update_component(
                    "agent_svid",
                    HealthStatus.HEALTHY,
                    "Agent SVID loaded from cache",
                    details={
                        "spiffe_id": self.current_agent_svid.spiffe_id,
                        "expiry": self.current_agent_svid.expiry.isoformat(),
                    },
                )

            self.health_manager.update_component(
                "icp_service",
                HealthStatus.HEALTHY,
                "ICP service client initialized",
            )

            # Step 6b: Configure mTLS on ICPClient using Agent SVID
            logger.info("Configuring mTLS with Agent SVID for workload attestation")
            agent_cert_path = self.settings.agent.data_dir / "agent_cert.pem"
            agent_key_path = self.settings.agent.data_dir / "agent_key.pem"
            agent_cert_path.write_text(self.current_agent_svid.certificate)
            agent_key_path.write_text(self.current_agent_svid.private_key)
            self.icp_client.client_cert_path = agent_cert_path
            self.icp_client.client_key_path = agent_key_path
            logger.info("mTLS credentials written for ICPClient")

            # Step 7: Initialize and start Workload API
            logger.info("Initializing Workload API")
            self.workload_manager = WorkloadManager(
                tenant_id=self.settings.agent.tenant_id,
                agent_spiffe_id=self.current_agent_svid.spiffe_id,
                icp_service_url=self.settings.icp_service.address,
                icp_client=self.icp_client,
            )
            await self.workload_manager.start()

            socket_path = str(self.settings.agent.socket_path)
            self.grpc_workload_server = GRPCWorkloadAPIServer(
                workload_manager=self.workload_manager,
                socket_path=socket_path,
            )
            await self.grpc_workload_server.start()

            self.health_manager.update_component(
                "workload_api",
                HealthStatus.HEALTHY,
                "Workload API server started",
            )

            # Step 8: Start background tasks
            logger.info("Starting background tasks")
            await self._start_background_tasks()

            # Mark agent as ready
            self.health_manager.set_ready(True)
            logger.info("Agent startup completed successfully")

        except Exception as e:
            logger.error("Agent startup failed", error=str(e), exc_info=True)
            raise

    async def _check_agent_svid(self) -> bool:
        """
        Check if a valid Agent SVID exists in cache.

        Returns:
            True if valid SVID exists, False otherwise
        """
        if not self.cert_cache:
            return False

        # Try to load Agent SVID from cache
        cached_svid = self.cert_cache.load_agent_svid()

        if cached_svid:
            # Check if it's expiring soon
            if cached_svid.is_expiring_soon(threshold_seconds=21600):  # 6 hours
                logger.info(
                    "Cached Agent SVID is expiring soon",
                    spiffe_id=cached_svid.spiffe_id,
                    expiry=cached_svid.expiry.isoformat(),
                )
                return False

            # SVID is valid
            self.current_agent_svid = cached_svid
            logger.info(
                "Valid Agent SVID loaded from cache",
                spiffe_id=cached_svid.spiffe_id,
                expiry=cached_svid.expiry.isoformat(),
            )
            return True

        return False

    async def _start_background_tasks(self) -> None:
        """Start all background tasks."""
        # Health check routine
        task = asyncio.create_task(self.health_manager.perform_health_checks())
        self._tasks.append(task)
        logger.info("Started health check task")

        # Agent SVID renewal routine
        task = asyncio.create_task(self._agent_svid_renewal_routine())
        self._tasks.append(task)
        logger.info("Started Agent SVID renewal task")

    async def _agent_svid_renewal_routine(self) -> None:
        """Background task for Agent SVID renewal."""
        logger.info("Agent SVID renewal routine started")

        while not self.shutdown_event.is_set():
            try:
                if not self.current_agent_svid or not self.node_attest_manager:
                    # Wait for initial attestation to complete
                    await asyncio.sleep(60)
                    continue

                # Check if SVID is expiring soon (6 hours threshold)
                if self.current_agent_svid.is_expiring_soon(threshold_seconds=21600):
                    logger.info(
                        "Agent SVID is expiring soon, starting renewal",
                        spiffe_id=self.current_agent_svid.spiffe_id,
                        expiry=self.current_agent_svid.expiry.isoformat(),
                    )

                    try:
                        # Renew Agent SVID
                        new_svid = await self.node_attest_manager.renew_agent_svid(
                            self.current_agent_svid
                        )
                        self.current_agent_svid = new_svid

                        # Update mTLS cert files and reset mTLS client so WorkloadManager uses new creds
                        agent_cert_path = self.settings.agent.data_dir / "agent_cert.pem"
                        agent_key_path = self.settings.agent.data_dir / "agent_key.pem"
                        agent_cert_path.write_text(new_svid.certificate)
                        agent_key_path.write_text(new_svid.private_key)
                        # Force ICPClient to recreate mTLS client with new cert on next request
                        if self.icp_client._mtls_client:
                            await self.icp_client._mtls_client.aclose()
                            self.icp_client._mtls_client = None

                        self.health_manager.update_component(
                            "agent_svid",
                            HealthStatus.HEALTHY,
                            "Agent SVID renewed successfully",
                            details={
                                "spiffe_id": new_svid.spiffe_id,
                                "expiry": new_svid.expiry.isoformat(),
                            },
                        )

                        logger.info(
                            "Agent SVID renewed successfully",
                            spiffe_id=new_svid.spiffe_id,
                            expiry=new_svid.expiry.isoformat(),
                        )

                    except Exception as e:
                        logger.error("Agent SVID renewal failed", error=str(e), exc_info=True)
                        self.health_manager.update_component(
                            "agent_svid",
                            HealthStatus.DEGRADED,
                            f"Agent SVID renewal failed: {str(e)}",
                        )

                # Sleep for 1 hour between checks
                await asyncio.sleep(3600)

            except Exception as e:
                logger.error("Error in SVID renewal routine", error=str(e), exc_info=True)
                await asyncio.sleep(60)

    async def shutdown(self) -> None:
        """
        Perform graceful shutdown.

        1. Stop accepting new requests
        2. Wait for in-flight requests to complete
        3. Cancel background tasks
        4. Close connections
        5. Cleanup resources
        """
        logger.info("Starting graceful shutdown")

        try:
            # Mark as not ready
            self.health_manager.set_ready(False)

            # Signal shutdown to all tasks
            self.shutdown_event.set()

            # Cancel all background tasks
            logger.info("Cancelling background tasks", task_count=len(self._tasks))
            for task in self._tasks:
                task.cancel()

            # Wait for tasks to complete with timeout
            if self._tasks:
                await asyncio.wait(self._tasks, timeout=10.0)

            # Close ICP service client
            if self.icp_client:
                await self.icp_client.close()
                logger.info("ICP client closed")

            # Stop Workload API server
            if self.grpc_workload_server:
                await self.grpc_workload_server.stop()
                logger.info("Workload API server stopped")
            if self.workload_manager:
                await self.workload_manager.stop()
                logger.info("Workload manager stopped")

            logger.info("Graceful shutdown completed")

        except Exception as e:
            logger.error("Error during shutdown", error=str(e), exc_info=True)

    def setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""

        def handle_shutdown_signal(signum: int, frame: Any) -> None:
            """Handle shutdown signals."""
            logger.info("Received shutdown signal", signal=signal.Signals(signum).name)
            asyncio.create_task(self.shutdown())

        # Register signal handlers
        signal.signal(signal.SIGTERM, handle_shutdown_signal)
        signal.signal(signal.SIGINT, handle_shutdown_signal)

        logger.info("Signal handlers registered")
