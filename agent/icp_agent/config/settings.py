"""
Configuration settings for ICP Agent.

Supports loading from:
1. YAML configuration file
2. Environment variables (ICP_AGENT_ prefix)
3. Command-line arguments
"""

import os
import re
from pathlib import Path
from typing import Optional
from functools import lru_cache

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _resolve_env_vars(obj):
    """Recursively resolve ${VAR} and ${VAR:-default} placeholders in config values."""
    if isinstance(obj, str):
        def _replace(match):
            var_expr = match.group(1)
            if ":-" in var_expr:
                var_name, default = var_expr.split(":-", 1)
                return os.environ.get(var_name, default)
            return os.environ.get(var_expr, match.group(0))
        return re.sub(r'\$\{([^}]+)\}', _replace, obj)
    elif isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_resolve_env_vars(item) for item in obj]
    return obj


class AgentConfig(BaseSettings):
    """Agent-specific configuration."""

    tenant_id: str = Field(default="", description="Tenant identifier")
    node_id: str = Field(default="", description="Unique node identifier")
    data_dir: Path = Field(
        default=Path("/var/lib/icp-agent"), description="Data directory for persistent storage"
    )
    socket_path: Path = Field(
        default=Path("/var/run/icp-agent/api.sock"), description="Unix socket path for Workload API"
    )
    renewal_threshold: str = Field(
        default="6h", description="Agent SVID renewal threshold duration"
    )


class ICPServiceConfig(BaseSettings):
    """ICP service connection configuration."""

    address: str = Field(default="https://prod.api.authsec.ai/spiresvc", description="ICP service address")
    trust_bundle_path: Path = Field(
        default=Path("/etc/icp-agent/trust-bundle.pem"),
        description="CA certificate path for ICP service",
    )
    timeout: int = Field(default=30, description="Connection timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_backoff: int = Field(default=5, description="Retry backoff in seconds")


class KubernetesAttestationConfig(BaseSettings):
    """Kubernetes attestation configuration."""

    token_path: Path = Field(
        default=Path("/var/run/secrets/kubernetes.io/serviceaccount/token"),
        description="Service account token path",
    )
    cluster_name: str = Field(default="", description="Cluster name")


class DockerAttestationConfig(BaseSettings):
    """Docker attestation configuration."""

    socket_path: Path = Field(
        default=Path("/var/run/docker.sock"), description="Docker socket path"
    )


class UnixAttestationConfig(BaseSettings):
    """Unix process attestation configuration."""

    method: str = Field(default="procfs", description="Process verification method")


class AttestationConfig(BaseSettings):
    """Attestation configuration."""

    type: str = Field(default="kubernetes", description="Attestation type")
    kubernetes: KubernetesAttestationConfig = Field(default_factory=KubernetesAttestationConfig)
    docker: DockerAttestationConfig = Field(default_factory=DockerAttestationConfig)
    unix: UnixAttestationConfig = Field(default_factory=UnixAttestationConfig)


class SecurityConfig(BaseSettings):
    """Security configuration."""

    cache_encryption_key: str = Field(
        default="", description="Encryption key for certificate cache (32 bytes base64)"
    )
    cache_path: Path = Field(
        default=Path("/var/lib/icp-agent/cache/svid.cache"),
        description="Certificate cache path",
    )


class LoggingConfig(BaseSettings):
    """Logging configuration."""

    level: str = Field(default="info", description="Log level")
    format: str = Field(default="json", description="Log format")
    file_path: str = Field(default="", description="Log file path")


class HealthConfig(BaseSettings):
    """Health check configuration."""

    enabled: bool = Field(default=True, description="Enable health check endpoint")
    port: int = Field(default=8080, description="Health check port")
    bind_address: str = Field(default="127.0.0.1", description="Health check bind address")


class Settings(BaseSettings):
    """Main settings class combining all configuration sections."""

    model_config = SettingsConfigDict(
        env_prefix="ICP_AGENT_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    agent: AgentConfig = Field(default_factory=AgentConfig)
    icp_service: ICPServiceConfig = Field(default_factory=ICPServiceConfig)
    attestation: AttestationConfig = Field(default_factory=AttestationConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)

    @classmethod
    def from_yaml(cls, config_path: str) -> "Settings":
        """Load settings from YAML file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)

        config_data = _resolve_env_vars(config_data)
        return cls(**config_data)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Settings":
        """
        Load settings with priority:
        1. YAML file (if provided)
        2. Environment variables
        3. Default values
        """
        if config_path and os.path.exists(config_path):
            # Load from YAML first, then override with env vars
            settings = cls.from_yaml(config_path)
            # Environment variables will automatically override due to pydantic_settings
            return settings

        # Load from environment variables and defaults
        return cls()

    def validate_required(self) -> None:
        """Validate that required fields are set."""
        if not self.agent.tenant_id:
            raise ValueError("agent.tenant_id is required")
        if not self.agent.node_id:
            raise ValueError("agent.node_id is required")

    def ensure_directories(self) -> None:
        """Ensure all required directories exist."""
        # Create data directory
        self.agent.data_dir.mkdir(parents=True, exist_ok=True)

        # Create socket directory
        self.agent.socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Create cache directory
        self.security.cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Create log directory if file logging is enabled
        if self.logging.file_path:
            Path(self.logging.file_path).parent.mkdir(parents=True, exist_ok=True)


@lru_cache()
def get_settings(config_path: Optional[str] = None) -> Settings:
    """Get cached settings instance."""
    return Settings.load(config_path)
