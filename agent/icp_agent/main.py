"""
ICP Agent main entry point.

Initializes and runs the ICP Agent with health check server and Workload API.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import structlog
import uvicorn
from uvicorn.config import LOGGING_CONFIG

from icp_agent.api.app import create_app
from icp_agent.config import Settings, get_settings
from icp_agent.core.lifecycle import AgentLifecycle
from icp_agent.log_config import setup_logging


logger: Optional[structlog.stdlib.BoundLogger] = None


async def main(config_path: Optional[str] = None) -> None:
    """
    Main entry point for ICP Agent.

    Args:
        config_path: Optional path to configuration file
    """
    global logger

    # Load settings
    settings = get_settings(config_path)

    # Setup logging
    setup_logging(
        level=settings.logging.level,
        log_format=settings.logging.format,
        log_file=settings.logging.file_path or None,
    )

    logger = structlog.get_logger(__name__)

    logger.info(
        "Starting ICP Agent",
        version="0.1.0",
        tenant_id=settings.agent.tenant_id,
        node_id=settings.agent.node_id,
    )

    # Create lifecycle manager
    lifecycle = AgentLifecycle(settings)

    try:
        # Perform startup sequence
        await lifecycle.startup()

        # Create FastAPI app for health checks
        app = create_app(settings, lifecycle.health_manager)

        # Configure uvicorn
        config = uvicorn.Config(
            app,
            host=settings.health.bind_address,
            port=settings.health.port,
            log_config=None,  # Disable uvicorn's logging (we use structlog)
            access_log=False,
        )

        server = uvicorn.Server(config)

        logger.info(
            "Starting health check server",
            bind_address=settings.health.bind_address,
            port=settings.health.port,
        )

        # Run server
        await server.serve()

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Fatal error", error=str(e), exc_info=True)
        sys.exit(1)
    finally:
        # Perform graceful shutdown
        await lifecycle.shutdown()
        logger.info("ICP Agent stopped")


def run() -> None:
    """Synchronous entry point for running the agent."""
    import argparse

    parser = argparse.ArgumentParser(description="ICP Agent")
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Path to configuration file (default: config.yaml)",
        default="config.yaml",
    )
    args = parser.parse_args()

    # Check if config file exists
    config_path = args.config if Path(args.config).exists() else None

    if not config_path:
        print(f"Warning: Configuration file '{args.config}' not found, using environment variables")

    # Run async main
    asyncio.run(main(config_path))


if __name__ == "__main__":
    run()
