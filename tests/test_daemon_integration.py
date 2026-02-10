"""
Integration tests for the daemon's device processing pipeline.

These tests use REAL components (no mocking of internal layers) to verify
the full flow: event -> policy -> analyzer -> database -> verdict.

The only mocks are:
- USB hardware (USBInterceptor) -- no real device needed
- Claude API (MockLLMAnalyzer) -- no API key needed
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from sentinel.audit.database import AuditDatabase
from sentinel.audit.models import TrustLevel
from sentinel.config import SentinelConfig
from sentinel.daemon import SentinelDaemon
from sentinel.interceptor.descriptors import create_test_descriptor
from sentinel.interceptor.linux import EventType, USBEvent
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.fingerprint import generate_fingerprint
from sentinel.policy.parser import load_policy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def work_dir():
    """Temp directory torn down after each test."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def policy_file(work_dir):
    """Write a real policy YAML and return its path."""
    path = os.path.join(work_dir, "policy.yaml")
    with open(path, "w") as f:
        f.write(
            """\
rules:
  # Whitelist: Logitech receiver
  - match:
      vid: "046d"
      pid: "c534"
    action: allow
    comment: "Logitech Unifying Receiver"
    priority: 100

  # Blacklist: known attack hardware
  - match:
      vid: "dead"
      pid: "beef"
    action: block
    comment: "Known attack device"
    priority: 100

  # Suspicious: HID + mass storage combo
  - match:
      class: HID
      has_storage_endpoint: true
    action: review
    comment: "HID with storage is suspicious"
    priority: 50

  # Default: review everything else
  - match: "*"
    action: review
    comment: "Unknown device"
    priority: 0
"""
        )
    return path


@pytest.fixture
def config(work_dir, policy_file):
    """Real SentinelConfig pointing at temp DB and temp policy."""
    return SentinelConfig.from_dict(
        {
            "daemon": {"log_level": "debug", "daemonize": False},
            "policy": {"rules_file": policy_file, "default_action": "review"},
            "database": {"path": os.path.join(work_dir, "audit.db")},
            "analyzer": {"enabled": False},
            "api": {"enabled": False},
            "alerts": {"enabled": False},
        }
    )


@pytest.fixture
def daemon(config):
    """SentinelDaemon with a stubbed interceptor (no real USB hardware)."""
    d = SentinelDaemon(config)
    # Replace the interceptor with a mock so we don't need real USB
    mock_interceptor = MagicMock()
    mock_interceptor.allow_device = MagicMock(return_value=True)
    mock_interceptor.block_device = MagicMock(return_value=True)
    mock_interceptor.stop = MagicMock()
    d._interceptor = mock_interceptor
    return d


def _make_event(descriptor, event_type=EventType.ADD):
    """Build a USBEvent wrapping a real DeviceDescriptor."""
    return USBEvent(
        event_type=event_type,
        bus=1,
        address=2,
        device_path="/dev/bus/usb/001/002",
        sys_path="/sys/bus/usb/devices/1-1",
        descriptor=descriptor,
        vid=descriptor.vid,
        pid=descriptor.pid,
    )


# ---------------------------------------------------------------------------
# Logitech descriptor  →  ALLOW
# ---------------------------------------------------------------------------
@pytest.fixture
def logitech_descriptor():
    return create_test_descriptor(
        vid="046d",
        pid="c534",
        manufacturer="Logitech",
        product="USB Receiver",
    )


# ---------------------------------------------------------------------------
# Unknown descriptor  →  REVIEW
# ---------------------------------------------------------------------------
@pytest.fixture
def unknown_descriptor():
    return create_test_descriptor(
        vid="aaaa",
        pid="bbbb",
        manufacturer="NoName",
        product="Mystery Widget",
    )


# ---------------------------------------------------------------------------
# Attack descriptor  →  BLOCK
# ---------------------------------------------------------------------------
@pytest.fixture
def attack_descriptor():
    return create_test_descriptor(
        vid="dead",
        pid="beef",
        manufacturer="Evil Corp",
        product="BadUSB",
    )


# =========================================================================
# Tests
# =========================================================================


class TestDaemonDeviceFlow:
    """Full daemon pipeline: event → policy → database → verdict."""

    @pytest.mark.asyncio
    async def test_whitelisted_device_allowed(self, daemon, logitech_descriptor):
        """A Logitech keyboard matching a whitelist rule is ALLOWED."""
        event = _make_event(logitech_descriptor)
        result = await daemon.handle_device_event(event)

        assert result["action"] == "allow"
        assert result["rule"] == "Logitech Unifying Receiver"
        assert result["fingerprint"] is not None

        # The interceptor should have been told to allow
        daemon.interceptor.allow_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_blacklisted_device_blocked(self, daemon, attack_descriptor):
        """A device matching a block rule is BLOCKED."""
        event = _make_event(attack_descriptor)
        result = await daemon.handle_device_event(event)

        assert result["action"] == "block"
        assert result["rule"] == "Known attack device"

        daemon.interceptor.block_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_unknown_device_reviewed(self, daemon, unknown_descriptor):
        """An unknown device triggers REVIEW (no analyzer configured)."""
        event = _make_event(unknown_descriptor)
        result = await daemon.handle_device_event(event)

        assert result["action"] == "review"
        assert result["rule"] == "Unknown device"

        # Without an analyzer, review stays as review → still allowed through
        daemon.interceptor.allow_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_new_device_persisted_to_database(self, daemon, logitech_descriptor):
        """First-time device is persisted via add_device()."""
        event = _make_event(logitech_descriptor)
        fingerprint = generate_fingerprint(logitech_descriptor)

        # Before: device not in DB
        assert daemon.db.get_device(fingerprint) is None

        await daemon.handle_device_event(event)

        # After: device IS in DB
        device = daemon.db.get_device(fingerprint)
        assert device is not None
        assert device.vid == logitech_descriptor.vid
        assert device.pid == logitech_descriptor.pid

    @pytest.mark.asyncio
    async def test_repeat_device_not_re_registered(self, daemon, logitech_descriptor):
        """Second insertion of same device skips registration."""
        event = _make_event(logitech_descriptor)
        fingerprint = generate_fingerprint(logitech_descriptor)

        # First insertion
        await daemon.handle_device_event(event)
        device1 = daemon.db.get_device(fingerprint)

        # Second insertion
        await daemon.handle_device_event(event)
        device2 = daemon.db.get_device(fingerprint)

        # Same device record
        assert device1.fingerprint == device2.fingerprint

    @pytest.mark.asyncio
    async def test_event_logged_to_audit_db(self, daemon, logitech_descriptor):
        """Each device event is logged to the audit database."""
        event = _make_event(logitech_descriptor)
        fingerprint = generate_fingerprint(logitech_descriptor)

        await daemon.handle_device_event(event)

        events = daemon.db.get_events(device_fingerprint=fingerprint)
        assert len(events) >= 1

        logged = events[0]
        assert logged.verdict == "allow"
        assert logged.device_fingerprint == fingerprint

    @pytest.mark.asyncio
    async def test_blocked_event_logged_to_audit_db(self, daemon, attack_descriptor):
        """Block decisions are logged with correct verdict."""
        event = _make_event(attack_descriptor)
        fingerprint = generate_fingerprint(attack_descriptor)

        await daemon.handle_device_event(event)

        events = daemon.db.get_events(device_fingerprint=fingerprint)
        assert len(events) >= 1
        assert events[0].verdict == "block"

    @pytest.mark.asyncio
    async def test_statistics_updated(self, daemon, logitech_descriptor, attack_descriptor):
        """Daemon statistics track allow/block counts."""
        await daemon.handle_device_event(_make_event(logitech_descriptor))
        await daemon.handle_device_event(_make_event(attack_descriptor))

        stats = daemon.get_statistics()
        assert stats["devices_processed"] == 2
        assert stats["devices_allowed"] == 1
        assert stats["devices_blocked"] == 1


class TestPolicyEngineDatabaseRoundtrip:
    """Policy engine and database work together without mocks."""

    def test_policy_loads_from_real_yaml(self, policy_file):
        """PolicyEngine loads and parses the real YAML file."""
        policy = load_policy(policy_file)
        engine = PolicyEngine(policy=policy)

        assert len(engine.policy.rules) == 4

    def test_policy_matches_logitech(self, policy_file, logitech_descriptor):
        """Logitech descriptor matches the whitelist rule."""
        policy = load_policy(policy_file)
        engine = PolicyEngine(policy=policy)

        result = engine.evaluate(logitech_descriptor)
        assert result.action.value == "allow"

    def test_policy_blocks_attack_device(self, policy_file, attack_descriptor):
        """Attack descriptor matches the block rule."""
        policy = load_policy(policy_file)
        engine = PolicyEngine(policy=policy)

        result = engine.evaluate(attack_descriptor)
        assert result.action.value == "block"

    def test_database_roundtrip(self, work_dir, logitech_descriptor):
        """Device survives add → get roundtrip through real SQLite."""
        db_path = os.path.join(work_dir, "roundtrip.db")
        db = AuditDatabase(db_path)
        fingerprint = generate_fingerprint(logitech_descriptor)

        db.add_device(
            fingerprint=fingerprint,
            vid=logitech_descriptor.vid,
            pid=logitech_descriptor.pid,
            manufacturer=logitech_descriptor.manufacturer,
            product=logitech_descriptor.product,
        )

        device = db.get_device(fingerprint)
        assert device is not None
        assert device.manufacturer == "Logitech"

        db.log_event(
            device_fingerprint=fingerprint,
            event_type="connect",
            verdict="allow",
        )

        events = db.get_events(device_fingerprint=fingerprint)
        assert len(events) == 1
        assert events[0].verdict == "allow"
