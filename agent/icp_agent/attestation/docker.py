"""
Docker attestation validator.

Collects Docker-specific attestation evidence including:
- Container ID
- Image name and digest
- Container labels
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional

import structlog

from .base import AttestationValidator
from icp_agent.config import DockerAttestationConfig


logger = structlog.get_logger(__name__)


class DockerValidator(AttestationValidator):
    """Docker attestation validator."""

    def __init__(self, config: DockerAttestationConfig):
        """
        Initialize Docker validator.

        Args:
            config: Docker attestation configuration
        """
        super().__init__(config)
        self.config: DockerAttestationConfig = config

    async def validate_environment(self) -> bool:
        """
        Validate that we're running in a Docker container.

        Returns:
            True if running in Docker, False otherwise
        """
        # Check for Docker-specific files
        cgroup_path = Path("/proc/self/cgroup")
        if not cgroup_path.exists():
            logger.warning("Unable to read /proc/self/cgroup")
            return False

        # Check cgroup for docker
        with open(cgroup_path, "r") as f:
            cgroup_content = f.read()
            if "docker" not in cgroup_content and "containerd" not in cgroup_content:
                logger.warning("Not running in Docker container")
                return False

        logger.info("Docker environment validated")
        return True

    async def collect_evidence(self) -> Dict[str, Any]:
        """
        Collect Docker attestation evidence.

        Returns:
            Dictionary containing:
            - container_id: Docker container ID
            - image_id: Docker image ID
            - image_name: Docker image name
            - hostname: Container hostname

        Raises:
            ValueError: If unable to collect evidence
        """
        logger.info("Collecting Docker attestation evidence")

        evidence = {}

        # Get container ID from cgroup
        container_id = self._get_container_id()
        if container_id:
            evidence["container_id"] = container_id

        # Get hostname (usually same as short container ID)
        hostname = os.getenv("HOSTNAME", "")
        if hostname:
            evidence["hostname"] = hostname

        # Get image information from environment variables
        # These should be set in the Dockerfile or docker run command
        if image_name := os.getenv("IMAGE_NAME"):
            evidence["image_name"] = image_name

        if image_id := os.getenv("IMAGE_ID"):
            evidence["image_id"] = image_id

        if image_digest := os.getenv("IMAGE_DIGEST"):
            evidence["image_digest"] = image_digest

        # Get container labels from environment (if available)
        labels = {}
        for key, value in os.environ.items():
            if key.startswith("LABEL_"):
                label_name = key[6:].lower()
                labels[label_name] = value

        if labels:
            evidence["labels"] = labels

        if not evidence:
            raise ValueError("Unable to collect Docker attestation evidence")

        logger.info(
            "Docker attestation evidence collected",
            container_id=container_id or "unknown",
            hostname=hostname or "unknown",
        )

        return evidence

    def _get_container_id(self) -> Optional[str]:
        """
        Extract container ID from cgroup file.

        Returns:
            Container ID or None if not found
        """
        cgroup_path = Path("/proc/self/cgroup")
        if not cgroup_path.exists():
            return None

        try:
            with open(cgroup_path, "r") as f:
                for line in f:
                    # Look for docker or containerd in cgroup
                    # Format: 12:cpuset:/docker/<container_id>
                    # or: 0::/system.slice/docker-<container_id>.scope
                    if match := re.search(r"docker[/-]([a-f0-9]{64})", line):
                        return match.group(1)
                    elif match := re.search(r"containerd[/-]([a-f0-9]{64})", line):
                        return match.group(1)
                    # Short container ID format
                    elif match := re.search(r"docker[/-]([a-f0-9]{12})", line):
                        return match.group(1)

        except Exception as e:
            logger.warning("Failed to read container ID from cgroup", error=str(e))

        return None

    def get_node_selectors(self) -> Dict[str, str]:
        """
        Get node selectors from Docker environment.

        Returns:
            Dictionary of node selectors (docker:container_id, docker:image, etc.)
        """
        selectors = {}

        if container_id := self._get_container_id():
            selectors["docker:container_id"] = container_id

        if hostname := os.getenv("HOSTNAME"):
            selectors["docker:hostname"] = hostname

        if image_name := os.getenv("IMAGE_NAME"):
            selectors["docker:image"] = image_name

        # Add labels as selectors
        for key, value in os.environ.items():
            if key.startswith("LABEL_"):
                label_name = key[6:].lower()
                selectors[f"docker:label:{label_name}"] = value

        return selectors
