#!/usr/bin/env python3
"""
ICP Agent - SPIRE-Compatible Agent

Complete SPIRE agent implementation:
1. Workload Manager - Manages workload attestation lifecycle
2. Workload API Server - Serves SVIDs to workloads via Unix socket
3. Auto-rotation - Rotates SVIDs before expiry
4. Selector Plugins - Kubernetes, Unix, Docker
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

from icp_agent.workload_manager import WorkloadManager
from icp_agent.grpc_workload_api import GRPCWorkloadAPIServer
from icp_agent.certificate_lifecycle import CertificateLifecycleManager
from icp_agent.health_monitor import HealthMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("icp-agent")


class ICPAgent:
    """
    ICP Agent - SPIRE-Compatible Agent

    Manages workload attestation and SVID lifecycle
    """

    def __init__(
        self,
        tenant_id: str,
        agent_spiffe_id: str,
        icp_service_url: str = "https://prod.api.authsec.ai/spiresvc",
        socket_path: str = "/tmp/spire-agent/public/api.sock"
    ):
        self.tenant_id = tenant_id
        self.agent_spiffe_id = agent_spiffe_id
        self.icp_service_url = icp_service_url
        self.socket_path = socket_path

        # Certificate Lifecycle Manager (Epic 8) - created first
        self.cert_lifecycle = CertificateLifecycleManager(
            workload_manager=None,  # Will be set after WorkloadManager is created
            rotation_threshold=0.6666,  # Rotate at 66.66% TTL (when 1/3 of TTL remains)
            check_interval=30,  # Check every 30 seconds
            logger=logger
        )

        # Workload Manager
        self.workload_manager = WorkloadManager(
            tenant_id=tenant_id,
            agent_spiffe_id=agent_spiffe_id,
            icp_service_url=icp_service_url,
            logger=logger,
            cert_lifecycle_manager=self.cert_lifecycle
        )

        # Set workload_manager in cert_lifecycle after creation
        self.cert_lifecycle.workload_manager = self.workload_manager

        # gRPC Workload API Server
        self.workload_api = GRPCWorkloadAPIServer(
            workload_manager=self.workload_manager,
            socket_path=socket_path,
            logger=logger
        )

        # Health Monitor (Epic 9)
        self.health_monitor = HealthMonitor(
            workload_manager=self.workload_manager,
            cert_lifecycle=self.cert_lifecycle,
            workload_api_server=self.workload_api,
            check_interval=60,  # Health check every 60s
            metrics_interval=30,  # Log metrics every 30s
            logger=logger
        )

        self.running = False

    async def start(self):
        """Start ICP Agent"""
        logger.info("=" * 60)
        logger.info("ICP Agent - SPIRE-Compatible Agent")
        logger.info("=" * 60)
        logger.info("")
        logger.info(f"Tenant ID: {self.tenant_id}")
        logger.info(f"Agent SPIFFE ID: {self.agent_spiffe_id}")
        logger.info(f"ICP Service: {self.icp_service_url}")
        logger.info(f"Workload API Socket: {self.socket_path}")
        logger.info("")

        # 1. Start Workload Manager
        logger.info("[1/4] Starting Workload Manager...")
        await self.workload_manager.start()
        logger.info("")

        # 2. Start Certificate Lifecycle Manager
        logger.info("[2/4] Starting Certificate Lifecycle Manager...")
        await self.cert_lifecycle.start()
        logger.info("")

        # 3. Start Workload API Server
        logger.info("[3/4] Starting Workload API Server...")
        await self.workload_api.start()
        logger.info("")

        # 4. Start Health Monitor
        logger.info("[4/4] Starting Health Monitor...")
        await self.health_monitor.start()
        logger.info("")

        logger.info("=" * 60)
        logger.info("✓ ICP Agent started successfully")
        logger.info("=" * 60)
        logger.info("")
        logger.info("Agent is ready to attest workloads!")
        logger.info("")
        logger.info("Workloads can now:")
        logger.info("  1. Connect to gRPC Workload API: " + self.socket_path)
        logger.info("  2. Call FetchX509SVID() to get their SVID")
        logger.info("  3. Receive automatic SVID rotation updates")
        logger.info("  4. Use SVIDs for mTLS communication")
        logger.info("")

        self.running = True

    async def stop(self):
        """Stop ICP Agent"""
        if not self.running:
            return

        logger.info("")
        logger.info("Shutting down ICP Agent...")

        # Stop Health Monitor
        await self.health_monitor.stop()

        # Stop Workload API Server
        await self.workload_api.stop()

        # Stop Certificate Lifecycle Manager
        await self.cert_lifecycle.stop()

        # Stop Workload Manager
        await self.workload_manager.stop()

        self.running = False

        logger.info("✓ ICP Agent stopped")

    async def run_maintenance_loop(self):
        """
        Run periodic maintenance tasks:
        - Refresh workload entries
        - Rotate expiring SVIDs
        - Clean up terminated workloads
        """
        while self.running:
            try:
                await asyncio.sleep(30)  # Run every 30 seconds

                if not self.running:
                    break

                logger.debug("Running maintenance tasks...")

                # Refresh workload entries (every 5 minutes)
                if not self.workload_manager.entries_last_updated:
                    await self.workload_manager.refresh_workload_entries()
                else:
                    # Convert both to naive UTC for consistent comparison
                    from datetime import datetime as dt
                    last_updated = self.workload_manager.entries_last_updated
                    # Remove timezone info if present to get naive UTC
                    if last_updated.tzinfo is not None:
                        last_updated = last_updated.replace(tzinfo=None)
                    # Use naive UTC datetime for comparison to avoid deprecation warning
                    now_utc = dt.now().replace(tzinfo=None) if dt.now().tzinfo else dt.now()
                    age = (now_utc - last_updated).total_seconds()
                    if age > 300:  # 5 minutes
                        await self.workload_manager.refresh_workload_entries()

                # Rotate expiring SVIDs
                await self.workload_manager.rotate_expired_svids()

                # TODO: Detect and clean up terminated workloads
                # This would require monitoring /proc or using process event notifications

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in maintenance loop: {e}")


async def main():
    """Main entry point for ICP Agent"""

    # Load configuration from config.yaml
    import yaml
    config_path = Path(__file__).parent / "config.yaml"

    if config_path.exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        TENANT_ID = config['agent']['tenant_id']
        NODE_ID = config['agent']['node_id']
        AGENT_SPIFFE_ID = f"spiffe://{TENANT_ID}/agent/{NODE_ID}"
        ICP_SERVICE_URL = config['icp_service']['address']
        SOCKET_PATH = config['agent']['socket_path']

        logger.info(f"Loaded configuration from {config_path}")
    else:
        # Fallback to hardcoded values
        logger.warning(f"Config file not found at {config_path}, using defaults")
        TENANT_ID = "4e615215-66b4-4414-bb39-4e0c6daa8f8b"
        AGENT_SPIFFE_ID = f"spiffe://{TENANT_ID}/agent/test-node-1"
        ICP_SERVICE_URL = "https://prod.api.authsec.ai/spiresvc"
        SOCKET_PATH = "/tmp/spire-agent/public/api.sock"

        # On Windows, use a different socket path
        if sys.platform == "win32":
            logger.warning("Windows detected - Unix socket support is limited")
            logger.warning("For production on Windows, use named pipes or TCP socket")
            SOCKET_PATH = "tcp://127.0.0.1:4000"

    # Create agent
    agent = ICPAgent(
        tenant_id=TENANT_ID,
        agent_spiffe_id=AGENT_SPIFFE_ID,
        icp_service_url=ICP_SERVICE_URL,
        socket_path=SOCKET_PATH
    )

    # Setup signal handlers
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        asyncio.create_task(agent.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start agent
    await agent.start()

    # Run maintenance loop
    try:
        await agent.run_maintenance_loop()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("")
        logger.info("Agent stopped by user")
