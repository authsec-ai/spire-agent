"""
ICP Service HTTP client with mTLS support.

Handles communication with the ICP service for node attestation,
agent renewal, and workload operations.
"""

import ssl
from pathlib import Path
from typing import Optional, Dict, Any

import httpx
import structlog
from pydantic import BaseModel, Field

from icp_agent.config import Settings


logger = structlog.get_logger(__name__)


class NodeAttestRequest(BaseModel):
    """Node attestation request."""

    tenant_id: str = Field(..., description="Tenant identifier")
    node_id: str = Field(..., description="Node identifier")
    attestation_type: str = Field(..., description="Attestation type")
    evidence: Dict[str, Any] = Field(..., description="Attestation evidence")
    csr: str = Field(..., description="Certificate signing request (PEM)")


class NodeAttestResponse(BaseModel):
    """Node attestation response."""

    agent_id: str = Field(..., description="Agent identifier")
    spiffe_id: str = Field(..., description="Agent SPIFFE ID")
    certificate: str = Field(..., description="Agent certificate (PEM)")
    ca_bundle: str = Field(..., description="CA bundle (PEM)")
    ttl: int = Field(..., description="Certificate TTL in seconds")


class AgentRenewRequest(BaseModel):
    """Agent SVID renewal request."""

    agent_id: str = Field(..., description="Agent identifier")
    tenant_id: str = Field(..., description="Tenant identifier")
    csr: str = Field(..., description="Certificate signing request (PEM)")


class AgentRenewResponse(BaseModel):
    """Agent SVID renewal response."""

    spiffe_id: str = Field(..., description="Agent SPIFFE ID")
    certificate: str = Field(..., description="Agent certificate (PEM)")
    ca_bundle: str = Field(..., description="CA bundle (PEM)")
    ttl: int = Field(..., description="Certificate TTL in seconds")


class WorkloadAttestRequest(BaseModel):
    """Workload attestation request."""

    workload_selectors: Dict[str, str] = Field(..., description="Workload selectors")
    csr: str = Field(..., description="Certificate signing request (PEM)")


class WorkloadAttestResponse(BaseModel):
    """Workload attestation response."""

    spiffe_id: str = Field(..., description="Workload SPIFFE ID")
    certificate: str = Field(..., description="Workload certificate (PEM)")
    ca_bundle: str = Field(..., description="CA bundle (PEM)")
    ttl: int = Field(..., description="Certificate TTL in seconds")


class ICPClient:
    """HTTP client for ICP service with mTLS support."""

    def __init__(
        self,
        settings: Settings,
        client_cert_path: Optional[Path] = None,
        client_key_path: Optional[Path] = None,
    ):
        """
        Initialize ICP client.

        Args:
            settings: Application settings
            client_cert_path: Path to client certificate (Agent SVID)
            client_key_path: Path to client private key
        """
        self.settings = settings
        self.base_url = settings.icp_service.address
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.tenant_id = settings.agent.tenant_id

        # Default headers sent on every request (used by relay for tenant routing)
        self._default_headers = {
            "X-Tenant-ID": self.tenant_id,
        }

        # Initialize HTTP client (without mTLS for node attestation)
        self._client: Optional[httpx.AsyncClient] = None
        self._mtls_client: Optional[httpx.AsyncClient] = None

        logger.info("ICP client initialized", base_url=self.base_url)

    async def _get_client(self, use_mtls: bool = False) -> httpx.AsyncClient:
        """
        Get HTTP client instance.

        Args:
            use_mtls: Whether to use mTLS authentication

        Returns:
            Configured HTTP client
        """
        if use_mtls:
            if not self._mtls_client:
                self._mtls_client = await self._create_mtls_client()
            return self._mtls_client
        else:
            if not self._client:
                self._client = await self._create_client()
            return self._client

    async def _create_client(self) -> httpx.AsyncClient:
        """Create HTTP client without mTLS (for node attestation)."""
        # Check if using HTTP (no TLS) or HTTPS
        if self.base_url.startswith("http://"):
            # HTTP - no TLS verification needed
            logger.info("Using HTTP (no TLS) for ICP service")
            return httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._default_headers,
                timeout=httpx.Timeout(self.settings.icp_service.timeout),
                verify=False,  # Disable SSL verification for HTTP
            )
        else:
            # HTTPS - use custom CA bundle if provided, otherwise system CAs
            ssl_context = ssl.create_default_context()
            if self.settings.icp_service.trust_bundle_path.exists():
                ssl_context.load_verify_locations(str(self.settings.icp_service.trust_bundle_path))
                logger.info("Using custom CA bundle", path=str(self.settings.icp_service.trust_bundle_path))
            else:
                logger.info("Using system CA trust store for ICP service TLS")

            return httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._default_headers,
                timeout=httpx.Timeout(self.settings.icp_service.timeout),
                verify=ssl_context,
            )

    async def _create_mtls_client(self) -> httpx.AsyncClient:
        """Create HTTP client with mTLS authentication."""
        # Check if using HTTP (no TLS/mTLS)
        if self.base_url.startswith("http://"):
            # HTTP - no mTLS, just regular HTTP
            logger.warning("mTLS requested but using HTTP (no TLS) - creating regular HTTP client")
            return httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._default_headers,
                timeout=httpx.Timeout(self.settings.icp_service.timeout),
                verify=False,
            )

        # HTTPS with mTLS
        if not self.client_cert_path or not self.client_key_path:
            raise ValueError("Client certificate and key required for mTLS")

        if not self.client_cert_path.exists():
            raise FileNotFoundError(f"Client certificate not found: {self.client_cert_path}")

        if not self.client_key_path.exists():
            raise FileNotFoundError(f"Client key not found: {self.client_key_path}")

        # Create SSL context with client certificate
        ssl_context = ssl.create_default_context()

        # Load CA bundle for server verification
        if self.settings.icp_service.trust_bundle_path.exists():
            ssl_context.load_verify_locations(str(self.settings.icp_service.trust_bundle_path))

        # Load client certificate and key
        ssl_context.load_cert_chain(
            certfile=str(self.client_cert_path),
            keyfile=str(self.client_key_path),
        )

        logger.info(
            "Created mTLS client",
            cert_path=str(self.client_cert_path),
            key_path=str(self.client_key_path),
        )

        return httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._default_headers,
            timeout=httpx.Timeout(self.settings.icp_service.timeout),
            verify=ssl_context,
        )

    async def node_attest(self, request: NodeAttestRequest) -> NodeAttestResponse:
        """
        Perform node attestation.

        Args:
            request: Node attestation request

        Returns:
            Node attestation response with Agent SVID

        Raises:
            httpx.HTTPError: If request fails
        """
        logger.info(
            "Performing node attestation",
            tenant_id=request.tenant_id,
            node_id=request.node_id,
            attestation_type=request.attestation_type,
        )

        client = await self._get_client(use_mtls=False)

        response = await client.post(
            "/v1/node/attest",
            json=request.model_dump(),
        )
        response.raise_for_status()

        result = NodeAttestResponse(**response.json())

        logger.info(
            "Node attestation successful",
            agent_id=result.agent_id,
            spiffe_id=result.spiffe_id,
            ttl=result.ttl,
        )

        return result

    async def renew_agent_svid(self, request: AgentRenewRequest) -> AgentRenewResponse:
        """
        Renew Agent SVID.

        Args:
            request: Agent renewal request

        Returns:
            Agent renewal response with new SVID

        Raises:
            httpx.HTTPError: If request fails
        """
        logger.info("Renewing Agent SVID", agent_id=request.agent_id)

        client = await self._get_client(use_mtls=True)

        response = await client.post(
            "/v1/agent/renew",
            json=request.model_dump(),
        )
        response.raise_for_status()

        result = AgentRenewResponse(**response.json())

        logger.info(
            "Agent SVID renewal successful",
            spiffe_id=result.spiffe_id,
            ttl=result.ttl,
        )

        return result

    async def attest_workload(self, request: WorkloadAttestRequest) -> WorkloadAttestResponse:
        """
        Attest workload and issue SVID.

        Args:
            request: Workload attestation request

        Returns:
            Workload attestation response with SVID

        Raises:
            httpx.HTTPError: If request fails
        """
        logger.info("Attesting workload", selectors=request.workload_selectors)

        client = await self._get_client(use_mtls=True)

        response = await client.post(
            "/v1/attest",
            json=request.model_dump(),
        )
        response.raise_for_status()

        result = WorkloadAttestResponse(**response.json())

        logger.info(
            "Workload attestation successful",
            spiffe_id=result.spiffe_id,
            ttl=result.ttl,
        )

        return result

    async def get_bundle(self, tenant_id: str) -> str:
        """
        Get trust bundle for tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            PEM-encoded CA bundle

        Raises:
            httpx.HTTPError: If request fails
        """
        logger.info("Fetching trust bundle", tenant_id=tenant_id)

        client = await self._get_client(use_mtls=False)

        response = await client.get(f"/bundle/{tenant_id}")
        response.raise_for_status()

        bundle = response.json()["ca_bundle"]

        logger.info("Trust bundle fetched successfully", tenant_id=tenant_id)

        return bundle

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check against ICP service.

        Returns:
            Health check response

        Raises:
            httpx.HTTPError: If request fails
        """
        client = await self._get_client(use_mtls=False)

        response = await client.get("/health")
        response.raise_for_status()

        return response.json()

    async def close(self) -> None:
        """Close HTTP clients."""
        if self._client:
            await self._client.aclose()
            self._client = None

        if self._mtls_client:
            await self._mtls_client.aclose()
            self._mtls_client = None

        logger.info("ICP client closed")

    async def __aenter__(self) -> "ICPClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()
