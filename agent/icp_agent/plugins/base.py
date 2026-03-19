"""
Base Selector Plugin Interface

All selector plugins must implement this interface.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
import logging


class SelectorPlugin(ABC):
    """
    Base class for selector collection plugins

    Selector plugins collect metadata about workloads and format them
    as SPIFFE selectors (key-value pairs).
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def get_selectors(self, pid: int) -> Dict[str, str]:
        """
        Collect selectors for a given process ID

        Args:
            pid: Process ID of the workload

        Returns:
            Dictionary of selectors (e.g., {"k8s:ns": "default", "k8s:sa": "app"})
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this plugin can run in the current environment

        Returns:
            True if plugin is available, False otherwise
        """
        pass

    @abstractmethod
    def get_plugin_name(self) -> str:
        """
        Get the name of this plugin

        Returns:
            Plugin name (e.g., "kubernetes", "unix", "docker")
        """
        pass
