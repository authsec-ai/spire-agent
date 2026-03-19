"""
ICP Agent Selector Plugins

Plugins for collecting workload selectors from different platforms:
- Kubernetes: Pod metadata, labels, service account
- Unix: Process UID, GID, path
- Docker: Container ID, image, labels
"""

from .base import SelectorPlugin
from .kubernetes_plugin import KubernetesPlugin
from .unix_plugin import UnixPlugin
from .docker_plugin import DockerPlugin

__all__ = [
    'SelectorPlugin',
    'KubernetesPlugin',
    'UnixPlugin',
    'DockerPlugin',
]
