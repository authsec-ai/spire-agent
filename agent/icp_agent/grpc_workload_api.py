"""
SPIFFE Workload API - gRPC Implementation

Implements the official SPIFFE Workload API over Unix Domain Socket using gRPC.
This replaces the HTTP/JSON implementation with full gRPC streaming support.

Based on: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md
"""

import asyncio
import logging
import os
from typing import Optional, Dict, AsyncIterator
import grpc
from grpc import aio
from datetime import datetime, timedelta

from .api import workload_pb2, workload_pb2_grpc


class WorkloadAPIServicer(workload_pb2_grpc.SpiffeWorkloadAPIServicer):
    """
    gRPC servicer implementing the SPIFFE Workload API
    """

    def __init__(self, workload_manager, logger: Optional[logging.Logger] = None):
        self.workload_manager = workload_manager
        self.logger = logger or logging.getLogger(__name__)

        # Track active streaming connections for SVID updates
        self.x509_subscribers: Dict[int, asyncio.Queue] = {}
        self.bundle_subscribers: Dict[int, asyncio.Queue] = {}

        # Metrics counters
        self.api_requests_total = 0
        self.api_errors_total = 0

        # Background task for SVID rotation notifications
        self.rotation_task: Optional[asyncio.Task] = None

    async def FetchX509SVID(
        self,
        request: workload_pb2.X509SVIDRequest,
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[workload_pb2.X509SVIDResponse]:
        """
        Streaming RPC that provides X.509-SVIDs to workloads.

        The stream:
        1. Immediately returns the current SVID
        2. Pushes updates when SVID is rotated
        3. Continues until client disconnects
        """
        self.logger.info("=" * 80)
        self.logger.info("FetchX509SVID RPC CALLED")
        self.logger.info("=" * 80)

        # Increment metrics
        self.api_requests_total += 1

        # Get PID from peer credentials (Unix socket)
        # For now, we'll use a simulated PID extraction
        # In production, this would use SO_PEERCRED socket option
        pid = self._get_peer_pid(context)
        metadata_selectors = self._extract_k8s_selectors(context)

        self.logger.info(f"FetchX509SVID stream started for PID {pid}")
        if metadata_selectors:
            self.logger.info(f"K8s selectors from metadata: {metadata_selectors}")

        # Create queue for this subscriber
        update_queue = asyncio.Queue()
        self.x509_subscribers[pid] = update_queue

        try:
            # Send initial SVID immediately
            svid = self.workload_manager.get_svid(pid)
            if not svid:
                self.logger.info(f"No cached SVID for PID {pid}, attesting...")
                svid = await self.workload_manager.attest_workload(pid, metadata_selectors=metadata_selectors)

            if not svid:
                self.logger.error(f"Failed to get SVID for PID {pid}")
                self.api_errors_total += 1
                context.set_code(grpc.StatusCode.PERMISSION_DENIED)
                context.set_details("Workload attestation failed")
                return

            # Send initial response
            response = self._build_x509_response(svid)
            yield response

            self.logger.info(f"Sent initial SVID to PID {pid}")
            self.logger.info(f"  SPIFFE ID: {svid.spiffe_id}")
            self.logger.info(f"  Expires: {svid.expires_at}")

            # Stream updates until client disconnects
            while True:
                try:
                    # Wait for update notification (with timeout to check for rotation)
                    try:
                        updated_svid = await asyncio.wait_for(
                            update_queue.get(),
                            timeout=30.0
                        )

                        # Send updated SVID
                        response = self._build_x509_response(updated_svid)
                        yield response

                        self.logger.info(f"Sent rotated SVID to PID {pid}")
                        self.logger.info(f"  New expires: {updated_svid.expires_at}")

                    except asyncio.TimeoutError:
                        # Check if SVID needs rotation
                        current_svid = self.workload_manager.get_svid(pid)
                        if current_svid and self.workload_manager.is_svid_expired(current_svid):
                            self.logger.info(f"SVID expiring soon for PID {pid}, rotating...")
                            new_svid = await self.workload_manager.attest_workload(pid)
                            if new_svid:
                                # Send rotated SVID
                                response = self._build_x509_response(new_svid)
                                yield response
                                self.logger.info(f"Sent auto-rotated SVID to PID {pid}")

                except asyncio.CancelledError:
                    self.logger.info(f"FetchX509SVID stream cancelled for PID {pid}")
                    break
                except Exception as e:
                    self.logger.error(f"Error in FetchX509SVID stream for PID {pid}: {e}")
                    self.api_errors_total += 1
                    break

        finally:
            # Clean up subscriber
            if pid in self.x509_subscribers:
                del self.x509_subscribers[pid]
            self.logger.info(f"FetchX509SVID stream ended for PID {pid}")

    async def FetchX509Bundles(
        self,
        request: workload_pb2.X509BundlesRequest,
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[workload_pb2.X509BundlesResponse]:
        """
        Streaming RPC that provides X.509 trust bundles.

        Streams updates when trust bundles are rotated.
        """
        pid = self._get_peer_pid(context)
        self.logger.info(f"FetchX509Bundles stream started for PID {pid}")

        # Create queue for bundle updates
        bundle_queue = asyncio.Queue()
        self.bundle_subscribers[pid] = bundle_queue

        try:
            # Get current SVID to extract trust bundle
            svid = self.workload_manager.get_svid(pid)
            if not svid:
                svid = await self.workload_manager.attest_workload(pid)

            if not svid:
                context.set_code(grpc.StatusCode.PERMISSION_DENIED)
                context.set_details("Workload not attested")
                return

            # Send initial bundle
            response = workload_pb2.X509BundlesResponse(
                bundles={
                    self.workload_manager.tenant_id: svid.trust_bundle.encode('utf-8')
                }
            )
            yield response

            self.logger.info(f"Sent initial trust bundle to PID {pid}")

            # Stream bundle updates
            while True:
                try:
                    # Wait for bundle update
                    updated_bundle = await asyncio.wait_for(
                        bundle_queue.get(),
                        timeout=60.0
                    )

                    response = workload_pb2.X509BundlesResponse(
                        bundles={
                            self.workload_manager.tenant_id: updated_bundle.encode('utf-8')
                        }
                    )
                    yield response

                    self.logger.info(f"Sent updated trust bundle to PID {pid}")

                except asyncio.TimeoutError:
                    # Heartbeat - no bundle update
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error in FetchX509Bundles stream: {e}")
                    break

        finally:
            if pid in self.bundle_subscribers:
                del self.bundle_subscribers[pid]
            self.logger.info(f"FetchX509Bundles stream ended for PID {pid}")

    async def FetchJWTSVID(
        self,
        request: workload_pb2.JWTSVIDRequest,
        context: grpc.aio.ServicerContext
    ) -> workload_pb2.JWTSVIDResponse:
        """
        RPC that provides JWT-SVIDs to workloads.

        Unlike X.509, this is not streaming - one request, one response.
        """
        pid = self._get_peer_pid(context)
        self.logger.info(f"FetchJWTSVID request from PID {pid}")
        self.logger.info(f"  Audience: {request.audience}")
        self.logger.info(f"  SPIFFE ID: {request.spiffe_id or 'default'}")

        # Get workload's X.509 SVID first (to verify identity)
        x509_svid = self.workload_manager.get_svid(pid)
        if not x509_svid:
            x509_svid = await self.workload_manager.attest_workload(pid)

        if not x509_svid:
            context.set_code(grpc.StatusCode.PERMISSION_DENIED)
            context.set_details("Workload not attested")
            return workload_pb2.JWTSVIDResponse()

        # Use requested SPIFFE ID or default to workload's identity
        spiffe_id = request.spiffe_id or x509_svid.spiffe_id

        # Request JWT-SVID from ICP service
        jwt_token = await self._request_jwt_svid(
            spiffe_id=spiffe_id,
            audience=list(request.audience)
        )

        if not jwt_token:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Failed to issue JWT-SVID")
            return workload_pb2.JWTSVIDResponse()

        # Build response
        jwt_svid = workload_pb2.JWTSVID(
            spiffe_id=spiffe_id,
            svid=jwt_token
        )

        response = workload_pb2.JWTSVIDResponse(svids=[jwt_svid])

        self.logger.info(f"Issued JWT-SVID to PID {pid}")
        self.logger.info(f"  SPIFFE ID: {spiffe_id}")
        self.logger.info(f"  Audience: {request.audience}")

        return response

    async def ValidateJWTSVID(
        self,
        request: workload_pb2.ValidateJWTSVIDRequest,
        context: grpc.aio.ServicerContext
    ) -> workload_pb2.ValidateJWTSVIDResponse:
        """
        RPC that validates JWT-SVIDs.
        """
        self.logger.info(f"ValidateJWTSVID request")
        self.logger.info(f"  Audience: {request.audience}")

        # Validate JWT with ICP service
        validation_result = await self._validate_jwt_svid(
            token=request.svid,
            audience=request.audience
        )

        if not validation_result:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("JWT validation failed")
            return workload_pb2.ValidateJWTSVIDResponse()

        # Build response
        response = workload_pb2.ValidateJWTSVIDResponse(
            spiffe_id=validation_result['spiffe_id'],
            claims=validation_result.get('claims', {})
        )

        self.logger.info(f"JWT-SVID validated successfully")
        self.logger.info(f"  SPIFFE ID: {validation_result['spiffe_id']}")

        return response

    async def FetchJWTBundles(
        self,
        request: workload_pb2.JWTBundlesRequest,
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[workload_pb2.JWTBundlesResponse]:
        """
        Streaming RPC that provides JWT bundles (JWKS).
        """
        pid = self._get_peer_pid(context)
        self.logger.info(f"FetchJWTBundles stream started for PID {pid}")

        try:
            # Get JWT bundle from ICP service
            jwt_bundle = await self._fetch_jwt_bundle()

            if not jwt_bundle:
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details("Failed to fetch JWT bundle")
                return

            # Send initial bundle
            response = workload_pb2.JWTBundlesResponse(
                bundles={
                    self.workload_manager.tenant_id: jwt_bundle.encode('utf-8')
                }
            )
            yield response

            self.logger.info(f"Sent JWT bundle to PID {pid}")

            # Stream updates (in production, this would watch for bundle rotation)
            while True:
                await asyncio.sleep(3600)  # Check hourly
                # In production: check for bundle updates and yield if changed

        except asyncio.CancelledError:
            self.logger.info(f"FetchJWTBundles stream cancelled for PID {pid}")
        except Exception as e:
            self.logger.error(f"Error in FetchJWTBundles stream: {e}")

    def _extract_k8s_selectors(self, context: grpc.aio.ServicerContext) -> Dict[str, str]:
        """
        Extract Kubernetes selectors from gRPC metadata sent by the workload SDK.

        The SDK sends headers like x-k8s-namespace, x-k8s-service-account, etc.
        These are converted to k8s:ns, k8s:sa selector format for matching against
        workload entries when the Kubernetes selector plugin is not available.
        """
        selectors = {}
        try:
            metadata = dict(context.invocation_metadata())

            # Map SDK metadata keys to selector keys
            metadata_to_selector = {
                'x-k8s-namespace': 'k8s:ns',
                'x-k8s-service-account': 'k8s:sa',
                'x-k8s-pod-name': 'k8s:pod-name',
                'x-k8s-pod-uid': 'k8s:pod-uid',
            }

            for meta_key, selector_key in metadata_to_selector.items():
                value = metadata.get(meta_key)
                if value:
                    selectors[selector_key] = value

            # Handle pod labels: x-k8s-pod-label-<name> -> k8s:pod-label:<name>
            for key, value in metadata.items():
                if key.startswith('x-k8s-pod-label-'):
                    label_name = key[len('x-k8s-pod-label-'):]
                    selectors[f'k8s:pod-label:{label_name}'] = value

        except Exception as e:
            self.logger.debug(f"Error extracting K8s selectors from metadata: {e}")

        return selectors

    def _get_peer_pid(self, context: grpc.aio.ServicerContext) -> int:
        """
        Extract PID from gRPC metadata or TCP connection.

        For TCP sockets, we get the PID from metadata sent by the client.
        For Unix sockets, we would use SO_PEERCRED (not implemented yet).
        """
        try:
            # Try to get PID from gRPC metadata (sent by client)
            metadata = dict(context.invocation_metadata())
            pid_str = metadata.get('x-pid')
            if pid_str:
                return int(pid_str)

            # Fallback: Try to get from peer address (TCP connection)
            peer = context.peer()
            self.logger.debug(f"gRPC peer info: {peer}")

            # For TCP connections from localhost, try to find the process
            # by checking /proc for open connections to our port
            if peer and 'ipv4:127.0.0.1' in peer:
                # Extract client port from peer string like "ipv4:127.0.0.1:12345"
                parts = peer.split(':')
                if len(parts) >= 3:
                    client_port = parts[-1]
                    # Find process with this connection
                    pid = self._find_process_by_connection(client_port)
                    if pid:
                        return pid

            # Last resort: log warning and use a default
            self.logger.warning(f"Could not determine caller PID from context, using default")
            # Return a sentinel value that will trigger an error
            return -1

        except Exception as e:
            self.logger.error(f"Error extracting PID from context: {e}")
            return -1

    def _find_process_by_connection(self, local_port: str) -> Optional[int]:
        """
        Find process ID by looking for TCP connection to local port.

        This is a workaround for TCP sockets where we don't have peer credentials.
        """
        try:
            import subprocess
            # Use netstat or ss to find the process
            result = subprocess.run(
                ['ss', '-tnp', f'sport = :{local_port}'],
                capture_output=True,
                text=True,
                timeout=1
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if 'pid=' in line:
                        # Extract PID from output like: users:(("python3",pid=12345,fd=3))
                        import re
                        match = re.search(r'pid=(\d+)', line)
                        if match:
                            return int(match.group(1))

            return None

        except Exception as e:
            self.logger.debug(f"Could not find process by connection: {e}")
            return None

    def _build_x509_response(self, svid) -> workload_pb2.X509SVIDResponse:
        """Build X509SVIDResponse from WorkloadSVID"""
        x509_svid = workload_pb2.X509SVID(
            spiffe_id=svid.spiffe_id,
            x509_svid=svid.certificate.encode('utf-8'),
            x509_svid_key=svid.private_key.encode('utf-8'),
            bundle=svid.trust_bundle.encode('utf-8')
        )

        response = workload_pb2.X509SVIDResponse(
            svids=[x509_svid],
            crl={},  # CRL not implemented yet
            federated_bundles={}  # Federation not implemented yet
        )

        return response

    async def _request_jwt_svid(self, spiffe_id: str, audience: list) -> Optional[str]:
        """Request JWT-SVID from ICP service"""
        try:
            import httpx

            url = f"{self.workload_manager.icp_service_url}/v1/jwt/issue"
            request_data = {
                "tenant_id": self.workload_manager.tenant_id,
                "spiffe_id": spiffe_id,
                "audience": audience,
                "ttl": 3600  # 1 hour
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=request_data)

                if response.status_code == 200:
                    data = response.json()
                    return data.get('token')
                else:
                    self.logger.error(f"JWT-SVID request failed: {response.status_code}")
                    return None

        except Exception as e:
            self.logger.error(f"Failed to request JWT-SVID: {e}")
            return None

    async def _validate_jwt_svid(self, token: str, audience: str) -> Optional[dict]:
        """Validate JWT-SVID with ICP service"""
        try:
            import httpx

            url = f"{self.workload_manager.icp_service_url}/v1/jwt/validate"
            request_data = {
                "tenant_id": self.workload_manager.tenant_id,
                "token": token,
                "audience": audience
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=request_data)

                if response.status_code == 200:
                    return response.json()
                else:
                    self.logger.error(f"JWT validation failed: {response.status_code}")
                    return None

        except Exception as e:
            self.logger.error(f"Failed to validate JWT-SVID: {e}")
            return None

    async def _fetch_jwt_bundle(self) -> Optional[str]:
        """Fetch JWT bundle (JWKS) from ICP service"""
        try:
            import httpx

            url = f"{self.workload_manager.icp_service_url}/v1/jwt/bundle"
            params = {"tenant_id": self.workload_manager.tenant_id}

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    return data.get('bundle')
                else:
                    self.logger.error(f"JWT bundle fetch failed: {response.status_code}")
                    return None

        except Exception as e:
            self.logger.error(f"Failed to fetch JWT bundle: {e}")
            return None

    async def notify_svid_rotation(self, pid: int, new_svid):
        """Notify subscribers of SVID rotation"""
        if pid in self.x509_subscribers:
            await self.x509_subscribers[pid].put(new_svid)

    async def notify_bundle_update(self, pid: int, new_bundle: str):
        """Notify subscribers of trust bundle update"""
        if pid in self.bundle_subscribers:
            await self.bundle_subscribers[pid].put(new_bundle)


class GRPCWorkloadAPIServer:
    """
    gRPC server for SPIFFE Workload API

    Listens on Unix Domain Socket and serves the Workload API via gRPC.
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

        self.server: Optional[aio.Server] = None
        self.servicer: Optional[WorkloadAPIServicer] = None

    async def start(self):
        """Start gRPC Workload API server"""
        self.logger.info("Starting gRPC SPIFFE Workload API Server")
        self.logger.info(f"  Socket Path: {self.socket_path}")

        # Determine if using TCP or Unix socket
        is_tcp = self.socket_path.startswith("tcp://")

        if is_tcp:
            # TCP socket - extract address
            bind_address = self.socket_path.replace("tcp://", "")
            self.logger.info(f"  Using TCP socket: {bind_address}")
        else:
            # Unix socket - remove existing socket if present
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)

            # Create directory if needed
            socket_dir = os.path.dirname(self.socket_path)
            if socket_dir and not os.path.exists(socket_dir):
                os.makedirs(socket_dir, mode=0o755)

            self.logger.info(f"  Using Unix socket: {self.socket_path}")

        # Create gRPC server
        self.server = aio.server()

        # Create and register servicer
        self.servicer = WorkloadAPIServicer(
            workload_manager=self.workload_manager,
            logger=self.logger
        )

        workload_pb2_grpc.add_SpiffeWorkloadAPIServicer_to_server(
            self.servicer,
            self.server
        )

        # Bind to socket
        if is_tcp:
            # Bind to TCP address
            self.server.add_insecure_port(bind_address)
        else:
            # Bind to Unix socket
            self.server.add_insecure_port(f'unix:{self.socket_path}')

        # Start server
        await self.server.start()

        # Set socket permissions (Unix only)
        if not is_tcp and os.path.exists(self.socket_path):
            os.chmod(self.socket_path, 0o666)

        self.logger.info("✓ gRPC Workload API Server started")
        if is_tcp:
            self.logger.info(f"  Listening on: {bind_address}")
        else:
            self.logger.info(f"  Listening on: {self.socket_path}")

    async def stop(self):
        """Stop gRPC server"""
        self.logger.info("Stopping gRPC Workload API Server")

        if self.server:
            await self.server.stop(grace=5.0)

        # Only remove Unix socket files
        is_tcp = self.socket_path.startswith("tcp://")
        if not is_tcp and os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        self.logger.info("✓ gRPC Workload API Server stopped")

    async def wait_for_termination(self):
        """Wait for server termination"""
        if self.server:
            await self.server.wait_for_termination()
