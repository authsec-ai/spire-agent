"""
Kubernetes PSAT (Projected Service Account Token) attestation validator.

Collects Kubernetes-specific attestation evidence including:
- Service account token
- Pod name
- Namespace
- Service account name
- Node name
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

import structlog

from .base import AttestationValidator
from icp_agent.config import KubernetesAttestationConfig


logger = structlog.get_logger(__name__)


class KubernetesValidator(AttestationValidator):
    """Kubernetes PSAT attestation validator."""

    def __init__(self, config: KubernetesAttestationConfig):
        """
        Initialize Kubernetes validator.

        Args:
            config: Kubernetes attestation configuration
        """
        super().__init__(config)
        self.config: KubernetesAttestationConfig = config

    async def validate_environment(self) -> bool:
        """
        Validate that we're running in a Kubernetes environment.

        Returns:
            True if running in Kubernetes, False otherwise
        """
        # Check for service account token
        if not self.config.token_path.exists():
            logger.warning(
                "Service account token not found",
                token_path=str(self.config.token_path),
            )
            return False

        # Check for Kubernetes environment variables
        if not os.getenv("KUBERNETES_SERVICE_HOST"):
            logger.warning("KUBERNETES_SERVICE_HOST not set")
            return False

        logger.info("Kubernetes environment validated")
        return True

    async def collect_evidence(self) -> Dict[str, Any]:
        """
        Collect Kubernetes attestation evidence.

        Returns:
            Dictionary containing:
            - psat_token: Service account token
            - cluster_name: Cluster name (if configured)
            - namespace: Pod namespace
            - pod_name: Pod name
            - service_account: Service account name
            - node_name: Node name

        Raises:
            FileNotFoundError: If service account token is not found
            ValueError: If required environment variables are missing
        """
        logger.info("Collecting Kubernetes attestation evidence")

        # Read service account token
        if not self.config.token_path.exists():
            raise FileNotFoundError(
                f"Service account token not found: {self.config.token_path}"
            )

        with open(self.config.token_path, "r") as f:
            psat_token = f.read().strip()

        # Read namespace from mounted file
        namespace_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        namespace = "default"
        if namespace_path.exists():
            with open(namespace_path, "r") as f:
                namespace = f.read().strip()
        else:
            # Fallback to environment variable
            namespace = os.getenv("POD_NAMESPACE", "default")

        # Get pod information from environment variables
        # These should be set via Downward API in pod spec
        pod_name = os.getenv("POD_NAME", "")
        service_account = os.getenv("SERVICE_ACCOUNT_NAME", "")
        node_name = os.getenv("NODE_NAME", "")

        if not pod_name:
            logger.warning(
                "POD_NAME environment variable not set. "
                "Add Downward API to pod spec: "
                "env.valueFrom.fieldRef.fieldPath=metadata.name"
            )

        if not service_account:
            logger.warning(
                "SERVICE_ACCOUNT_NAME environment variable not set. "
                "Add Downward API to pod spec: "
                "env.valueFrom.fieldRef.fieldPath=spec.serviceAccountName"
            )

        if not node_name:
            logger.warning(
                "NODE_NAME environment variable not set. "
                "Add Downward API to pod spec: "
                "env.valueFrom.fieldRef.fieldPath=spec.nodeName"
            )

        evidence = {
            "psat_token": psat_token,
            "namespace": namespace,
        }

        # Add optional fields if available
        if self.config.cluster_name:
            evidence["cluster_name"] = self.config.cluster_name

        if pod_name:
            evidence["pod_name"] = pod_name

        if service_account:
            evidence["service_account"] = service_account

        if node_name:
            evidence["node_name"] = node_name

        logger.info(
            "Kubernetes attestation evidence collected",
            namespace=namespace,
            pod_name=pod_name or "unknown",
            has_token=bool(psat_token),
        )

        return evidence

    def get_node_selectors(self) -> Dict[str, str]:
        """
        Get node selectors from environment.

        Returns:
            Dictionary of node selectors (k8s:namespace, k8s:sa, k8s:pod, k8s:node)
        """
        selectors = {}

        namespace_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        if namespace_path.exists():
            with open(namespace_path, "r") as f:
                selectors["k8s:namespace"] = f.read().strip()

        if pod_name := os.getenv("POD_NAME"):
            selectors["k8s:pod"] = pod_name

        if sa_name := os.getenv("SERVICE_ACCOUNT_NAME"):
            selectors["k8s:sa"] = sa_name

        if node_name := os.getenv("NODE_NAME"):
            selectors["k8s:node"] = node_name

        if self.config.cluster_name:
            selectors["k8s:cluster"] = self.config.cluster_name

        return selectors
