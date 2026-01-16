"""
Pytest configuration and shared fixtures for USB Sentinel tests.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest
import yaml


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_config(temp_dir: Path) -> Path:
    """Create a sample configuration file."""
    config_path = temp_dir / "sentinel.yaml"
    config_data = {
        "daemon": {
            "daemonize": False,
            "log_level": "debug",
        },
        "policy": {
            "rules_file": str(temp_dir / "policy.yaml"),
            "default_action": "review",
        },
        "database": {
            "path": str(temp_dir / "test.db"),
        },
        "analyzer": {
            "enabled": False,
        },
        "api": {
            "enabled": True,
            "port": 8080,
        },
    }
    with open(config_path, "w") as f:
        yaml.dump(config_data, f)
    return config_path


@pytest.fixture
def sample_policy(temp_dir: Path) -> Path:
    """Create a sample policy file."""
    policy_path = temp_dir / "policy.yaml"
    policy_data = {
        "rules": [
            {
                "match": {"vid": "046d", "pid": "c534"},
                "action": "allow",
                "comment": "Test device",
            },
            {
                "match": {"class": "HID", "has_storage_endpoint": True},
                "action": "review",
                "comment": "Suspicious",
            },
            {
                "match": "*",
                "action": "review",
                "comment": "Default",
            },
        ]
    }
    with open(policy_path, "w") as f:
        yaml.dump(policy_data, f)
    return policy_path


@pytest.fixture
def sample_device_descriptor() -> dict:
    """Sample USB device descriptor for testing."""
    return {
        "vid": "046d",
        "pid": "c534",
        "device_class": 0,
        "device_subclass": 0,
        "device_protocol": 0,
        "manufacturer": "Logitech",
        "product": "USB Receiver",
        "serial": "ABC123",
        "interfaces": [
            {
                "interface_class": 3,  # HID
                "interface_subclass": 1,
                "interface_protocol": 1,
                "num_endpoints": 1,
                "endpoints": [
                    {
                        "address": 0x81,
                        "attributes": 0x03,
                        "max_packet_size": 8,
                        "interval": 10,
                    }
                ],
            }
        ],
    }


@pytest.fixture
def suspicious_device_descriptor() -> dict:
    """Suspicious USB device descriptor for testing."""
    return {
        "vid": "1234",
        "pid": "5678",
        "device_class": 0,
        "device_subclass": 0,
        "device_protocol": 0,
        "manufacturer": "USB Device",
        "product": "USB Device",
        "serial": None,
        "interfaces": [
            {
                "interface_class": 3,  # HID
                "interface_subclass": 0,
                "interface_protocol": 0,
                "num_endpoints": 3,
                "endpoints": [],
            },
            {
                "interface_class": 8,  # Mass Storage
                "interface_subclass": 6,
                "interface_protocol": 80,
                "num_endpoints": 2,
                "endpoints": [],
            },
        ],
    }
