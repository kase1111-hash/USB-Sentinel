"""
Configuration management for USB Sentinel.

Handles loading, validation, and access to daemon configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# Default configuration paths
DEFAULT_CONFIG_PATH = Path("/etc/usb-sentinel/sentinel.yaml")
DEFAULT_POLICY_PATH = Path("/etc/usb-sentinel/policy.yaml")
DEFAULT_DB_PATH = Path("/var/lib/usb-sentinel/audit.db")


@dataclass
class DaemonConfig:
    """Daemon general settings."""

    daemonize: bool = False
    pid_file: str = "/var/run/usb-sentinel.pid"
    log_level: str = "info"
    log_file: str | None = "/var/log/usb-sentinel.log"


@dataclass
class PolicyConfig:
    """Policy engine settings."""

    rules_file: str = str(DEFAULT_POLICY_PATH)
    default_action: str = "review"
    hot_reload: bool = True


@dataclass
class DatabaseConfig:
    """Database settings."""

    path: str = str(DEFAULT_DB_PATH)
    wal_mode: bool = True
    backup_interval: int = 24


@dataclass
class LocalLLMConfig:
    """Local LLM settings."""

    model_path: str = "/opt/usb-sentinel/models/llama-2-7b.gguf"
    n_ctx: int = 2048
    n_gpu_layers: int = 0


@dataclass
class AnalyzerConfig:
    """LLM Analyzer settings."""

    enabled: bool = True
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: str | None = None
    max_tokens: int = 1024
    timeout: int = 30
    rate_limit: int = 60
    local: LocalLLMConfig = field(default_factory=LocalLLMConfig)

    def __post_init__(self) -> None:
        # Load API key from environment if not set
        if self.api_key is None:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        # Convert dict to LocalLLMConfig if needed
        if isinstance(self.local, dict):
            self.local = LocalLLMConfig(**self.local)


@dataclass
class InterceptorConfig:
    """USB Interceptor settings."""

    platform: str = "auto"
    block_during_analysis: bool = True
    analysis_timeout: int = 10
    bypass_classes: list[int] = field(default_factory=list)


@dataclass
class APIConfig:
    """API server settings."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    cors_enabled: bool = True
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )
    auth_mode: str = "api_key"
    api_key: str | None = None

    def __post_init__(self) -> None:
        # Load API key from environment if not set
        if self.api_key is None:
            self.api_key = os.environ.get("SENTINEL_API_KEY")


@dataclass
class AlertMethods:
    """Alert notification methods."""

    desktop: bool = True
    syslog: bool = True
    webhook: str | None = None


@dataclass
class AlertConfig:
    """Alert settings."""

    enabled: bool = True
    threshold: int = 75
    methods: AlertMethods = field(default_factory=AlertMethods)

    def __post_init__(self) -> None:
        # Convert dict to AlertMethods if needed
        if isinstance(self.methods, dict):
            self.methods = AlertMethods(**self.methods)


@dataclass
class SentinelConfig:
    """Main configuration container."""

    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    interceptor: InterceptorConfig = field(default_factory=InterceptorConfig)
    api: APIConfig = field(default_factory=APIConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SentinelConfig:
        """Create configuration from dictionary."""
        return cls(
            daemon=DaemonConfig(**data.get("daemon", {})),
            policy=PolicyConfig(**data.get("policy", {})),
            database=DatabaseConfig(**data.get("database", {})),
            analyzer=AnalyzerConfig(**data.get("analyzer", {})),
            interceptor=InterceptorConfig(**data.get("interceptor", {})),
            api=APIConfig(**data.get("api", {})),
            alerts=AlertConfig(**data.get("alerts", {})),
        )


def load_config(path: str | Path | None = None) -> SentinelConfig:
    """
    Load configuration from YAML file.

    Args:
        path: Path to configuration file. If None, uses default paths.

    Returns:
        SentinelConfig instance with loaded settings.

    Raises:
        FileNotFoundError: If config file not found and no defaults available.
        yaml.YAMLError: If config file is invalid YAML.
    """
    if path is None:
        # Try default locations
        candidates = [
            DEFAULT_CONFIG_PATH,
            Path("config/sentinel.yaml"),
            Path("sentinel.yaml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path is None:
        # Return default configuration
        return SentinelConfig()

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    return SentinelConfig.from_dict(data)


def validate_config(config: SentinelConfig) -> list[str]:
    """
    Validate configuration and return list of errors.

    Args:
        config: Configuration to validate.

    Returns:
        List of error messages. Empty list if valid.
    """
    errors: list[str] = []

    # Validate log level
    valid_log_levels = {"debug", "info", "warning", "error"}
    if config.daemon.log_level not in valid_log_levels:
        errors.append(f"Invalid log_level: {config.daemon.log_level}")

    # Validate default action
    valid_actions = {"allow", "block", "review"}
    if config.policy.default_action not in valid_actions:
        errors.append(f"Invalid default_action: {config.policy.default_action}")

    # Validate analyzer provider
    valid_providers = {"anthropic", "local"}
    if config.analyzer.provider not in valid_providers:
        errors.append(f"Invalid analyzer provider: {config.analyzer.provider}")

    # Validate API key presence when analyzer is enabled
    if config.analyzer.enabled and config.analyzer.provider == "anthropic":
        if not config.analyzer.api_key:
            errors.append("Anthropic API key required when analyzer is enabled")

    # Validate port ranges
    if not (1 <= config.api.port <= 65535):
        errors.append(f"Invalid API port: {config.api.port}")

    # Validate alert threshold
    if not (0 <= config.alerts.threshold <= 100):
        errors.append(f"Invalid alert threshold: {config.alerts.threshold}")

    # Validate auth mode
    valid_auth_modes = {"none", "api_key", "mtls"}
    if config.api.auth_mode not in valid_auth_modes:
        errors.append(f"Invalid auth_mode: {config.api.auth_mode}")

    return errors
