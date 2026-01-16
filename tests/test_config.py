"""
Tests for configuration loading and validation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.config import (
    AnalyzerConfig,
    APIConfig,
    DaemonConfig,
    DatabaseConfig,
    SentinelConfig,
    load_config,
    validate_config,
)


class TestSentinelConfig:
    """Tests for SentinelConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = SentinelConfig()

        assert config.daemon.daemonize is False
        assert config.daemon.log_level == "info"
        assert config.policy.default_action == "review"
        assert config.analyzer.provider == "anthropic"
        assert config.api.port == 8000

    def test_from_dict(self) -> None:
        """Test creating config from dictionary."""
        data = {
            "daemon": {"log_level": "debug"},
            "api": {"port": 9000},
        }
        config = SentinelConfig.from_dict(data)

        assert config.daemon.log_level == "debug"
        assert config.api.port == 9000
        # Check defaults still work
        assert config.daemon.daemonize is False

    def test_from_dict_empty(self) -> None:
        """Test creating config from empty dictionary."""
        config = SentinelConfig.from_dict({})

        assert config.daemon.log_level == "info"
        assert config.api.port == 8000


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_from_file(self, sample_config: Path) -> None:
        """Test loading configuration from file."""
        config = load_config(sample_config)

        assert config.daemon.log_level == "debug"
        assert config.api.port == 8080
        assert config.analyzer.enabled is False

    def test_load_missing_file(self, temp_dir: Path) -> None:
        """Test loading from non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_config(temp_dir / "nonexistent.yaml")

    def test_load_default_when_no_path(self) -> None:
        """Test loading returns default config when no file found."""
        # This should return default config, not raise
        config = load_config(None)
        assert isinstance(config, SentinelConfig)

    def test_load_invalid_yaml(self, temp_dir: Path) -> None:
        """Test loading invalid YAML raises error."""
        bad_file = temp_dir / "bad.yaml"
        bad_file.write_text("invalid: yaml: content: [")

        with pytest.raises(yaml.YAMLError):
            load_config(bad_file)


class TestValidateConfig:
    """Tests for validate_config function."""

    def test_valid_config(self) -> None:
        """Test validation passes for valid config."""
        config = SentinelConfig()
        config.analyzer.enabled = False  # Skip API key check
        errors = validate_config(config)
        assert errors == []

    def test_invalid_log_level(self) -> None:
        """Test validation catches invalid log level."""
        config = SentinelConfig()
        config.daemon.log_level = "invalid"
        config.analyzer.enabled = False

        errors = validate_config(config)
        assert any("log_level" in e for e in errors)

    def test_invalid_default_action(self) -> None:
        """Test validation catches invalid default action."""
        config = SentinelConfig()
        config.policy.default_action = "invalid"
        config.analyzer.enabled = False

        errors = validate_config(config)
        assert any("default_action" in e for e in errors)

    def test_missing_api_key(self) -> None:
        """Test validation catches missing API key when analyzer enabled."""
        config = SentinelConfig()
        config.analyzer.enabled = True
        config.analyzer.api_key = None

        errors = validate_config(config)
        assert any("API key" in e for e in errors)

    def test_invalid_port(self) -> None:
        """Test validation catches invalid port numbers."""
        config = SentinelConfig()
        config.api.port = 99999
        config.analyzer.enabled = False

        errors = validate_config(config)
        assert any("port" in e for e in errors)

    def test_invalid_alert_threshold(self) -> None:
        """Test validation catches invalid alert threshold."""
        config = SentinelConfig()
        config.alerts.threshold = 150
        config.analyzer.enabled = False

        errors = validate_config(config)
        assert any("threshold" in e for e in errors)


class TestAnalyzerConfig:
    """Tests for AnalyzerConfig."""

    def test_api_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test API key loaded from environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

        config = AnalyzerConfig()
        assert config.api_key == "test-key-123"

    def test_api_key_explicit_overrides_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test explicit API key overrides environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")

        config = AnalyzerConfig(api_key="explicit-key")
        assert config.api_key == "explicit-key"


class TestAPIConfig:
    """Tests for APIConfig."""

    def test_api_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test API key loaded from environment."""
        monkeypatch.setenv("SENTINEL_API_KEY", "sentinel-key-123")

        config = APIConfig()
        assert config.api_key == "sentinel-key-123"
