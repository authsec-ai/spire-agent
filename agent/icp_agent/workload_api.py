"""
SPIFFE Workload API Server

Implements the SPIFFE Workload API over Unix Domain Socket.
For simplicity, we use HTTP/JSON over Unix socket instead of gRPC.
In production, this would use gRPC as defined in workload.proto.

Workloads connect to the Unix socket and fetch their SVIDs.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict
from aiohttp import web
import aiohttp.web_runner
from aiohttp.web import Application, Request, Response


class WorkloadAPIServer:
    """
    SPIFFE Workload API Server

    Listens on Unix Domain Socket and serves SVIDs to workloads
    """

    def __init__(
        self,
        workload_manager,
        socket_path: str = "/tmp/spire-agent/public/api.sock",
        logger: Optional[logging.Logger] = None
    ):
        self.workload_manager = workload_manager
        self.socket_path = socket_path
        self.logger = logger or logging.getLogger(__name__)
        self.app: Optional[Application] = None
        self.runner: Optional[aiohttp.web_runner.AppRunner] = None
        self.site: Optional[aiohttp.web_runner.UnixSite] = None

    async def start(self):
        """Start Workload API server"""
        self.logger.info("Starting SPIFFE Workload API Server")
        self.logger.info(f"  Socket Path: {self.socket_path}")

        # Create directory if it doesn't exist
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir and not os.path.exists(socket_dir):
            os.makedirs(socket_dir, mode=0o755)

        # Remove existing socket if present
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        # Create aiohttp application
        self.app = web.Application()

        # Register routes
        self.app.router.add_get('/svid', self.handle_fetch_svid)
        self.app.router.add_get('/health', self.handle_health)

        # Start server on Unix socket
        self.runner = aiohttp.web_runner.AppRunner(self.app)
        await self.runner.setup()

        self.site = aiohttp.web_runner.UnixSite(self.runner, self.socket_path)
        await self.site.start()

        # Set socket permissions (readable by all, writable by owner)
        os.chmod(self.socket_path, 0o666)

        self.logger.info("✓ Workload API Server started")
        self.logger.info(f"  Listening on: {self.socket_path}")

    async def stop(self):
        """Stop Workload API server"""
        self.logger.info("Stopping Workload API Server")

        if self.site:
            await self.site.stop()

        if self.runner:
            await self.runner.cleanup()

        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        self.logger.info("✓ Workload API Server stopped")

    async def handle_health(self, request: Request) -> Response:
        """Health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'service': 'workload-api',
            'socket': self.socket_path
        })

    async def handle_fetch_svid(self, request: Request) -> Response:
        """
        Fetch X.509 SVID for the calling workload

        The workload is identified by its process ID (PID).
        We get the PID from Unix socket peer credentials.
        """
        try:
            # Get PID of the calling process
            # In a real implementation, we'd get this from Unix socket peer credentials
            # For demo purposes, we accept PID as a query parameter
            pid_str = request.query.get('pid')

            if not pid_str:
                return web.json_response(
                    {'error': 'Missing pid parameter'},
                    status=400
                )

            pid = int(pid_str)

            self.logger.info(f"SVID request from PID {pid}")

            # Get SVID from workload manager
            svid = self.workload_manager.get_svid(pid)

            if not svid:
                # Workload not yet attested - trigger attestation
                self.logger.info(f"Workload PID {pid} not yet attested, triggering attestation...")
                svid = await self.workload_manager.attest_workload(pid)

                if not svid:
                    return web.json_response(
                        {'error': 'Failed to attest workload'},
                        status=500
                    )

            # Return SVID in SPIFFE Workload API format
            response_data = {
                'svids': [
                    {
                        'spiffe_id': svid.spiffe_id,
                        'x509_svid': svid.certificate,
                        'x509_svid_key': svid.private_key,
                        'bundle': svid.trust_bundle,
                        'expires_at': svid.expires_at.isoformat(),
                        'ttl': svid.ttl
                    }
                ]
            }

            self.logger.info(f"✓ Returning SVID for PID {pid}")
            self.logger.info(f"  SPIFFE ID: {svid.spiffe_id}")

            return web.json_response(response_data)

        except ValueError:
            return web.json_response(
                {'error': 'Invalid PID format'},
                status=400
            )
        except Exception as e:
            self.logger.error(f"Error fetching SVID: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )


class WorkloadAPIClient:
    """
    SPIFFE Workload API Client

    Connects to the Workload API server via Unix socket and fetches SVIDs
    """

    def __init__(
        self,
        socket_path: str = "/tmp/spire-agent/public/api.sock",
        logger: Optional[logging.Logger] = None
    ):
        self.socket_path = socket_path
        self.logger = logger or logging.getLogger(__name__)

    async def fetch_x509_svid(self, pid: Optional[int] = None) -> Optional[Dict]:
        """
        Fetch X.509 SVID from Workload API

        Args:
            pid: Process ID (optional, defaults to current process)

        Returns:
            SVID data dictionary or None
        """
        if pid is None:
            pid = os.getpid()

        try:
            # Create Unix socket connector
            connector = aiohttp.UnixConnector(path=self.socket_path)

            async with aiohttp.ClientSession(connector=connector) as session:
                url = f"http://localhost/svid?pid={pid}"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    else:
                        error_text = await response.text()
                        self.logger.error(f"Failed to fetch SVID: {response.status}")
                        self.logger.error(f"Error: {error_text}")
                        return None

        except Exception as e:
            self.logger.error(f"Failed to connect to Workload API: {e}")
            return None

    def get_svid(self, svid_data: Dict) -> Optional[Dict]:
        """
        Extract SVID from response data

        Args:
            svid_data: Response from fetch_x509_svid()

        Returns:
            First SVID or None
        """
        if svid_data and 'svids' in svid_data and len(svid_data['svids']) > 0:
            return svid_data['svids'][0]
        return None

    async def get_spiffe_id(self, pid: Optional[int] = None) -> Optional[str]:
        """
        Get SPIFFE ID for a process

        Args:
            pid: Process ID (optional)

        Returns:
            SPIFFE ID or None
        """
        svid_data = await self.fetch_x509_svid(pid)
        svid = self.get_svid(svid_data)
        return svid['spiffe_id'] if svid else None

    async def get_certificate(self, pid: Optional[int] = None) -> Optional[str]:
        """
        Get X.509 certificate for a process

        Args:
            pid: Process ID (optional)

        Returns:
            Certificate (PEM) or None
        """
        svid_data = await self.fetch_x509_svid(pid)
        svid = self.get_svid(svid_data)
        return svid['x509_svid'] if svid else None

    async def get_private_key(self, pid: Optional[int] = None) -> Optional[str]:
        """
        Get private key for a process

        Args:
            pid: Process ID (optional)

        Returns:
            Private key (PEM) or None
        """
        svid_data = await self.fetch_x509_svid(pid)
        svid = self.get_svid(svid_data)
        return svid['x509_svid_key'] if svid else None

    async def get_trust_bundle(self, pid: Optional[int] = None) -> Optional[str]:
        """
        Get trust bundle for a process

        Args:
            pid: Process ID (optional)

        Returns:
            Trust bundle (PEM) or None
        """
        svid_data = await self.fetch_x509_svid(pid)
        svid = self.get_svid(svid_data)
        return svid['bundle'] if svid else None
