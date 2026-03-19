"""Base attestation validator interface."""

from abc import ABC, abstractmethod
from typing import Dict, Any

import structlog


logger = structlog.get_logger(__name__)


class AttestationValidator(ABC):
    """Base class for node attestation validators."""

    def __init__(self, config: Any):
        """
        Initialize attestation validator.

        Args:
            config: Attestation-specific configuration
        """
        self.config = config
        logger.info(
            "Attestation validator initialized",
            validator_type=self.__class__.__name__,
        )

    @abstractmethod
    async def collect_evidence(self) -> Dict[str, Any]:
        """
        Collect attestation evidence.

        Returns:
            Dictionary containing attestation evidence

        Raises:
            Exception: If evidence collection fails
        """
        pass

    @abstractmethod
    async def validate_environment(self) -> bool:
        """
        Validate that the current environment supports this attestation method.

        Returns:
            True if environment is valid, False otherwise
        """
        pass

    def get_attestation_type(self) -> str:
        """
        Get the attestation type identifier.

        Returns:
            Attestation type string (e.g., "kubernetes", "docker", "unix")
        """
        return self.__class__.__name__.replace("Validator", "").lower()
