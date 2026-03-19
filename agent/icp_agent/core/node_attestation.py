"""
Node attestation manager.

Handles the node attestation process with the ICP service.
"""

from pathlib import Path
from typing import Optional

import structlog

from icp_agent.attestation import (
    AttestationValidator,
    KubernetesValidator,
    DockerValidator,
    UnixValidator,
)
from icp_agent.cache import CachedSVID, CertificateCache
from icp_agent.client import ICPClient, NodeAttestRequest
from icp_agent.config import Settings
from icp_agent.crypto import generate_key_and_csr, get_certificate_expiry


logger = structlog.get_logger(__name__)


class NodeAttestationManager:
    """Manages node attestation and Agent SVID lifecycle."""

    def __init__(
        self,
        settings: Settings,
        icp_client: ICPClient,
        cert_cache: CertificateCache,
    ):
        """
        Initialize node attestation manager.

        Args:
            settings: Application settings
            icp_client: ICP service client
            cert_cache: Certificate cache
        """
        self.settings = settings
        self.icp_client = icp_client
        self.cert_cache = cert_cache
        self.validator: Optional[AttestationValidator] = None
        self.agent_id: Optional[str] = None
        self.agent_spiffe_id: Optional[str] = None

        logger.info("Node attestation manager initialized")

    async def initialize(self) -> None:
        """Initialize attestation validator based on configuration."""
        attestation_type = self.settings.attestation.type.lower()

        if attestation_type == "kubernetes":
            self.validator = KubernetesValidator(self.settings.attestation.kubernetes)
        elif attestation_type == "docker":
            self.validator = DockerValidator(self.settings.attestation.docker)
        elif attestation_type == "unix":
            self.validator = UnixValidator(self.settings.attestation.unix)
        else:
            raise ValueError(f"Unsupported attestation type: {attestation_type}")

        # Validate environment
        if not await self.validator.validate_environment():
            raise RuntimeError(
                f"Environment validation failed for {attestation_type} attestation"
            )

        logger.info(
            "Attestation validator initialized",
            attestation_type=attestation_type,
        )

    async def perform_node_attestation(self) -> CachedSVID:
        """
        Perform node attestation with ICP service.

        Returns:
            Cached SVID with Agent certificate

        Raises:
            RuntimeError: If attestation fails
        """
        if not self.validator:
            raise RuntimeError("Attestation validator not initialized")

        logger.info("Starting node attestation process")

        try:
            # Step 1: Collect attestation evidence
            logger.info("Collecting attestation evidence")
            evidence = await self.validator.collect_evidence()

            # Step 2: Generate SPIFFE ID for agent
            # Format: spiffe://{tenant}/agent/{node-id}
            spiffe_id = f"spiffe://{self.settings.agent.tenant_id}/agent/{self.settings.agent.node_id}"

            # Step 3: Generate private key and CSR
            logger.info("Generating private key and CSR", spiffe_id=spiffe_id)
            private_key_pem, csr_pem = generate_key_and_csr(
                spiffe_id=spiffe_id,
                common_name=f"ICP Agent - {self.settings.agent.node_id}",
            )

            # Step 4: Send attestation request to ICP service
            logger.info("Sending attestation request to ICP service")
            request = NodeAttestRequest(
                tenant_id=self.settings.agent.tenant_id,
                node_id=self.settings.agent.node_id,
                attestation_type=self.validator.get_attestation_type(),
                evidence=evidence,
                csr=csr_pem,
            )

            response = await self.icp_client.node_attest(request)

            # Step 5: Save Agent SVID to cache
            logger.info(
                "Node attestation successful",
                agent_id=response.agent_id,
                spiffe_id=response.spiffe_id,
                ttl=response.ttl,
            )

            # Store agent ID for future use
            self.agent_id = response.agent_id
            self.agent_spiffe_id = response.spiffe_id

            # Get certificate expiry
            expiry = get_certificate_expiry(response.certificate)

            # Create cached SVID
            cached_svid = CachedSVID(
                spiffe_id=response.spiffe_id,
                certificate=response.certificate,
                private_key=private_key_pem,
                trust_bundle=response.ca_bundle,
                expiry=expiry,
            )

            # Save to cache
            self.cert_cache.save_agent_svid(cached_svid)

            logger.info(
                "Agent SVID saved to cache",
                spiffe_id=response.spiffe_id,
                expiry=expiry.isoformat(),
            )

            return cached_svid

        except Exception as e:
            logger.error("Node attestation failed", error=str(e), exc_info=True)
            raise RuntimeError(f"Node attestation failed: {e}")

    async def renew_agent_svid(self, current_svid: CachedSVID) -> CachedSVID:
        """
        Renew Agent SVID.

        Args:
            current_svid: Current Agent SVID

        Returns:
            New cached SVID

        Raises:
            RuntimeError: If renewal fails
        """
        if not self.agent_id:
            raise RuntimeError("Agent ID not set, perform node attestation first")

        logger.info("Starting Agent SVID renewal")

        try:
            # Step 1: Generate new private key and CSR
            logger.info("Generating new private key and CSR")
            private_key_pem, csr_pem = generate_key_and_csr(
                spiffe_id=current_svid.spiffe_id,
                common_name=f"ICP Agent - {self.settings.agent.node_id}",
            )

            # Step 2: Send renewal request to ICP service
            from icp_agent.client import AgentRenewRequest

            logger.info("Sending renewal request to ICP service")
            request = AgentRenewRequest(
                agent_id=self.agent_id,
                tenant_id=self.settings.agent.tenant_id,
                csr=csr_pem,
            )

            # Update mTLS client with current certificate
            # Save current SVID to temporary files for mTLS
            temp_cert_path = self.settings.agent.data_dir / "temp_agent_cert.pem"
            temp_key_path = self.settings.agent.data_dir / "temp_agent_key.pem"

            temp_cert_path.write_text(current_svid.certificate)
            temp_key_path.write_text(current_svid.private_key)

            # Create new ICP client with mTLS
            mtls_client = ICPClient(
                self.settings,
                client_cert_path=temp_cert_path,
                client_key_path=temp_key_path,
            )

            try:
                response = await mtls_client.renew_agent_svid(request)

                logger.info(
                    "Agent SVID renewal successful",
                    spiffe_id=response.spiffe_id,
                    ttl=response.ttl,
                )

                # Get certificate expiry
                expiry = get_certificate_expiry(response.certificate)

                # Create new cached SVID
                new_svid = CachedSVID(
                    spiffe_id=response.spiffe_id,
                    certificate=response.certificate,
                    private_key=private_key_pem,
                    trust_bundle=response.ca_bundle,
                    expiry=expiry,
                )

                # Save to cache
                self.cert_cache.save_agent_svid(new_svid)

                logger.info(
                    "New Agent SVID saved to cache",
                    spiffe_id=response.spiffe_id,
                    expiry=expiry.isoformat(),
                )

                return new_svid

            finally:
                # Cleanup temporary files
                if temp_cert_path.exists():
                    temp_cert_path.unlink()
                if temp_key_path.exists():
                    temp_key_path.unlink()

                await mtls_client.close()

        except Exception as e:
            logger.error("Agent SVID renewal failed", error=str(e), exc_info=True)
            raise RuntimeError(f"Agent SVID renewal failed: {e}")
