"""
Docker Selector Plugin

Collects selectors from Docker container metadata:
- docker:container-id
- docker:container-name
- docker:image-id
- docker:image-name
- docker:label:* (container labels)
"""

import os
import logging
from typing import Dict, Optional
import docker
from docker.errors import DockerException
from .base import SelectorPlugin


class DockerPlugin(SelectorPlugin):
    """
    Docker selector plugin

    Queries Docker API to get container metadata for a given process.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.docker_client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize Docker client"""
        try:
            self.docker_client = docker.from_env()
            # Test connection
            self.docker_client.ping()
            self.logger.info("Docker client initialized successfully")
        except DockerException as e:
            self.logger.warning(f"Could not connect to Docker: {e}")
            self.docker_client = None

    def is_available(self) -> bool:
        """Check if Docker API is available"""
        return self.docker_client is not None

    def get_plugin_name(self) -> str:
        """Get plugin name"""
        return "docker"

    def get_selectors(self, pid: int) -> Dict[str, str]:
        """
        Collect Docker selectors for a process

        Args:
            pid: Process ID

        Returns:
            Dictionary of selectors
        """
        if not self.is_available():
            self.logger.debug("Docker plugin not available")
            return {}

        selectors = {}

        try:
            # Get container ID from cgroup
            container_id = self._get_container_id_from_cgroup(pid)
            if not container_id:
                self.logger.debug(f"Could not determine container ID for PID {pid}")
                return {}

            # Get container details from Docker API
            container = self._get_container(container_id)
            if not container:
                self.logger.warning(f"Could not find container {container_id}")
                return {}

            # Extract selectors from container
            selectors = self._extract_selectors(container)

            self.logger.info(f"Collected {len(selectors)} Docker selectors for PID {pid}")

        except Exception as e:
            self.logger.error(f"Failed to collect Docker selectors: {e}")

        return selectors

    def _get_container_id_from_cgroup(self, pid: int) -> Optional[str]:
        """
        Extract container ID from process cgroup

        Docker sets cgroup paths like:
        /docker/<container-id>
        """
        try:
            cgroup_path = f"/proc/{pid}/cgroup"
            if not os.path.exists(cgroup_path):
                return None

            with open(cgroup_path, 'r') as f:
                for line in f:
                    if 'docker' in line:
                        # Extract container ID from cgroup path
                        # Example: 0::/docker/1234567890abcdef...
                        parts = line.split('/')
                        for i, part in enumerate(parts):
                            if part == 'docker' and i + 1 < len(parts):
                                # Container ID is the next part
                                container_id = parts[i + 1].strip()
                                # Docker IDs are typically 64 chars, but we can work with short IDs
                                if len(container_id) >= 12:
                                    return container_id[:64]  # Full ID if available

        except Exception as e:
            self.logger.debug(f"Could not read cgroup for PID {pid}: {e}")

        return None

    def _get_container(self, container_id: str) -> Optional[docker.models.containers.Container]:
        """
        Get container object from Docker API

        Args:
            container_id: Container ID (full or short)

        Returns:
            Container object or None
        """
        try:
            return self.docker_client.containers.get(container_id)
        except DockerException as e:
            self.logger.error(f"Docker API error: {e}")
            return None

    def _extract_selectors(self, container: docker.models.containers.Container) -> Dict[str, str]:
        """
        Extract selectors from container metadata

        Args:
            container: Docker container object

        Returns:
            Dictionary of selectors
        """
        selectors = {}

        # Container ID
        if container.id:
            selectors['docker:container-id'] = container.id

        # Container Name (remove leading '/')
        if container.name:
            name = container.name.lstrip('/')
            selectors['docker:container-name'] = name

        # Image ID
        if container.image and hasattr(container.image, 'id'):
            # Image ID format: sha256:abcdef...
            image_id = container.image.id
            if ':' in image_id:
                image_id = image_id.split(':', 1)[1][:12]  # Short ID
            selectors['docker:image-id'] = image_id

        # Image Name (tags)
        if container.image and hasattr(container.image, 'tags') and container.image.tags:
            # Use first tag
            selectors['docker:image-name'] = container.image.tags[0]

        # Container Labels
        if container.labels:
            for key, value in container.labels.items():
                # Format: docker:label:<label-key>
                selector_key = f'docker:label:{key}'
                selectors[selector_key] = value

        # Environment Variables (optional, but can be useful for matching)
        # Note: Be careful with sensitive data in env vars
        # if container.attrs and 'Config' in container.attrs:
        #     env_vars = container.attrs['Config'].get('Env', [])
        #     for env_var in env_vars:
        #         if '=' in env_var:
        #             key, value = env_var.split('=', 1)
        #             selector_key = f'docker:env:{key}'
        #             selectors[selector_key] = value

        return selectors
