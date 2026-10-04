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
from unittest.mock import AsyncMock, MagicMock

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


# ---------------------------------------------------------------------------
# Suspicious descriptor  →  held (anonymous HID keyboard)
# ---------------------------------------------------------------------------
@pytest.fixture
def suspicious_descriptor():
    return create_test_descriptor(
        vid="cccc",
        pid="dddd",
        manufacturer=None,
        product="Keyboard",
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
    async def test_unknown_clean_device_scored_locally(self, daemon, unknown_descriptor):
        """A review without an LLM is decided by local checks, not left open."""
        event = _make_event(unknown_descriptor)
        result = await daemon.handle_device_event(event)

        assert result["rule"] == "Unknown device"
        assert result["risk_score"] is not None
        assert result["action"] == "allow"
        daemon.interceptor.allow_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_unresolved_review_holds_device(self, daemon, suspicious_descriptor):
        """A medium-risk device is kept unauthorized until an operator decides."""
        event = _make_event(suspicious_descriptor)
        result = await daemon.handle_device_event(event)

        assert result["action"] == "review"
        assert 50 < result["risk_score"] <= 75
        daemon.interceptor.block_device.assert_called_once_with(event)
        daemon.interceptor.allow_device.assert_not_called()

        device = daemon.db.get_device(result["fingerprint"])
        assert device.trust_level == TrustLevel.REVIEW.value
        assert daemon.db.get_events(device_fingerprint=result["fingerprint"])[0].event_type == (
            "reviewed"
        )

    @pytest.mark.asyncio
    async def test_held_device_stays_held_when_replugged(self, daemon, suspicious_descriptor):
        """Re-plugging must not turn a held device into a 'known' allowed one."""
        first = await daemon.handle_device_event(_make_event(suspicious_descriptor))
        second = await daemon.handle_device_event(_make_event(suspicious_descriptor))

        assert first["action"] == second["action"] == "review"

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


class TestOperatorDecisions:
    """`usb-sentinel devices trust` must change what the daemon does."""

    @pytest.mark.asyncio
    async def test_trusted_overrides_block_rule(self, daemon, attack_descriptor):
        result = await daemon.handle_device_event(_make_event(attack_descriptor))
        assert result["action"] == "block"

        daemon.db.update_trust_level(result["fingerprint"], TrustLevel.TRUSTED)
        daemon.interceptor.reset_mock()

        event = _make_event(attack_descriptor)
        result = await daemon.handle_device_event(event)
        assert result["action"] == "allow"
        assert result["reason"] == "Trusted by operator"
        daemon.interceptor.allow_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_blocked_overrides_allow_rule(self, daemon, logitech_descriptor):
        fingerprint = generate_fingerprint(logitech_descriptor)
        daemon.db.add_device(fingerprint=fingerprint, vid="046d", pid="c534")
        daemon.db.update_trust_level(fingerprint, TrustLevel.BLOCKED)

        result = await daemon.handle_device_event(_make_event(logitech_descriptor))
        assert result["action"] == "block"

    @pytest.mark.asyncio
    async def test_trusting_held_device_allows_it(self, daemon, suspicious_descriptor):
        held = await daemon.handle_device_event(_make_event(suspicious_descriptor))
        daemon.db.update_trust_level(held["fingerprint"], TrustLevel.TRUSTED)

        result = await daemon.handle_device_event(_make_event(suspicious_descriptor))
        assert result["action"] == "allow"
        # The daemon must not overwrite the operator's decision
        assert daemon.db.get_device(held["fingerprint"]).trust_level == "trusted"


class TestEventStream:
    """Real udev streams contain more than ADD events with descriptors."""

    @pytest.mark.asyncio
    async def test_remove_event_logs_disconnect(self, daemon, logitech_descriptor):
        added = await daemon.handle_device_event(_make_event(logitech_descriptor))
        removed = USBEvent(
            event_type=EventType.REMOVE,
            bus=1,
            address=2,
            device_path="",
            sys_path="/sys/bus/usb/devices/1-1",
            vid="046d",
            pid="c534",
        )

        assert await daemon.handle_device_event(removed) is None
        types = [
            e.event_type for e in daemon.db.get_events(device_fingerprint=added["fingerprint"])
        ]
        assert "disconnect" in types

    @pytest.mark.asyncio
    async def test_remove_of_unknown_device_is_ignored(self, daemon):
        removed = USBEvent(EventType.REMOVE, 3, 4, "", "/sys/bus/usb/devices/3-1")
        assert await daemon.handle_device_event(removed) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("event_type", [EventType.BIND, EventType.UNBIND])
    async def test_bind_events_are_ignored(self, daemon, event_type):
        event = USBEvent(event_type, 1, 2, "", "/sys/bus/usb/devices/1-1")
        assert await daemon.handle_device_event(event) is None
        daemon.interceptor.allow_device.assert_not_called()
        daemon.interceptor.block_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_unreadable_device_is_blocked(self, daemon):
        event = USBEvent(EventType.ADD, 1, 2, "", "/sys/bus/usb/devices/1-1", vid="dead")
        assert await daemon.handle_device_event(event) is None
        daemon.interceptor.block_device.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_process_event_survives_errors(self, daemon, logitech_descriptor):
        """One failing event must not stop the daemon (it used to exit)."""
        daemon.interceptor.allow_device.side_effect = OSError("sysfs gone")
        assert await daemon.process_event(_make_event(logitech_descriptor)) is None

        daemon.interceptor.allow_device.side_effect = None
        result = await daemon.process_event(_make_event(logitech_descriptor))
        assert result["action"] == "allow"


class TestAnalysisPipeline:
    @pytest.mark.asyncio
    async def test_spoofed_vendor_escalates_allow_rule(self, daemon):
        """An allow rule for a VID does not cover a device that lies about its vendor."""
        fake = create_test_descriptor(
            vid="046d", pid="c534", manufacturer="Totally Legit", product="USB Receiver"
        )
        result = await daemon.handle_device_event(_make_event(fake))

        assert result["rule"] == "Logitech Unifying Receiver"
        assert result["risk_score"] is not None
        assert result["action"] != "allow"

    @pytest.mark.asyncio
    async def test_llm_cannot_lower_local_score(self, daemon, suspicious_descriptor):
        """Device strings reach the LLM, so its verdict may only add risk."""
        from sentinel.analyzer.scoring import AnalysisResult, Verdict

        llm = MagicMock()
        llm.analyze_async = AsyncMock(
            return_value=AnalysisResult(0, Verdict.ALLOW, "looks fine", confidence=1.0)
        )
        daemon._analyzer, daemon._analyzer_checked = llm, True

        result = await daemon.handle_device_event(_make_event(suspicious_descriptor))
        assert result["action"] == "review"
        assert "llm=0" in result["reason"]

    @pytest.mark.asyncio
    async def test_llm_can_raise_score(self, daemon, unknown_descriptor):
        from sentinel.analyzer.scoring import AnalysisResult, Verdict

        llm = MagicMock()
        llm.analyze_async = AsyncMock(
            return_value=AnalysisResult(90, Verdict.BLOCK, "keystroke injector", confidence=0.9)
        )
        daemon._analyzer, daemon._analyzer_checked = llm, True

        result = await daemon.handle_device_event(_make_event(unknown_descriptor))
        assert result["action"] == "block"
        assert "keystroke injector" in result["analysis"]

    @pytest.mark.asyncio
    async def test_llm_timeout_falls_back_to_local(self, daemon, unknown_descriptor):
        async def slow(*_args, **_kwargs):
            await asyncio.sleep(10)

        llm = MagicMock()
        llm.analyze_async = slow
        daemon._analyzer, daemon._analyzer_checked = llm, True
        daemon.config.interceptor.analysis_timeout = 0.05

        result = await daemon.handle_device_event(_make_event(unknown_descriptor))
        assert result["action"] == "allow"
        assert "llm" not in result["reason"]

    @pytest.mark.asyncio
    async def test_first_seen_rule_uses_audit_database(self, work_dir, config):
        """`first_seen` must stop matching once the device is on record."""
        policy_path = os.path.join(work_dir, "first_seen.yaml")
        with open(policy_path, "w") as f:
            f.write(
                "rules:\n"
                "  - match: {first_seen: true}\n"
                "    action: block\n"
                "    comment: new\n"
                "  - match: '*'\n"
                "    action: allow\n"
            )
        config.policy.rules_file = policy_path
        d = SentinelDaemon(config)
        d._interceptor = MagicMock()

        device = create_test_descriptor(vid="1111", pid="2222")
        first = await d.handle_device_event(_make_event(device))
        second = await d.handle_device_event(_make_event(device))

        assert first["action"] == "block"
        assert second["action"] == "allow"


class TestLifecycle:
    @pytest.fixture
    def lifecycle_daemon(self, config, work_dir):
        config.daemon.pid_file = os.path.join(work_dir, "run", "sentinel.pid")
        config.daemon.log_file = None
        config.policy.hot_reload = False
        d = SentinelDaemon(config)
        d._interceptor = MagicMock()
        d._interceptor.start.return_value = []
        return d

    @pytest.mark.asyncio
    async def test_pid_file_written_and_removed(self, lifecycle_daemon):
        pid_file = lifecycle_daemon.config.daemon.pid_file
        await lifecycle_daemon.start()
        with open(pid_file) as f:
            assert int(f.read()) == os.getpid()

        await lifecycle_daemon.stop()
        assert not os.path.exists(pid_file)
        lifecycle_daemon._interceptor.stop.assert_called()

    @pytest.mark.asyncio
    async def test_refuses_second_instance(self, lifecycle_daemon):
        pid_file = lifecycle_daemon.config.daemon.pid_file
        os.makedirs(os.path.dirname(pid_file))
        with open(pid_file, "w") as f:
            f.write(str(os.getppid()))  # a live process that is not us

        with pytest.raises(RuntimeError, match="already|running"):
            await lifecycle_daemon.start()
        lifecycle_daemon._interceptor.start.assert_not_called()

    @pytest.mark.asyncio
    async def test_pending_devices_processed_on_start(self, lifecycle_daemon, logitech_descriptor):
        """Devices plugged in while the daemon was down get a verdict at startup."""
        pending = _make_event(logitech_descriptor)
        lifecycle_daemon._interceptor.start.return_value = [pending]

        async def no_events():
            return
            yield

        lifecycle_daemon._interceptor.events = no_events
        await lifecycle_daemon.run()

        lifecycle_daemon._interceptor.allow_device.assert_called_once_with(pending)

    @pytest.mark.asyncio
    async def test_start_failure_releases_interceptor(self, lifecycle_daemon):
        """If startup fails after the buses were locked down, unlock them."""
        lifecycle_daemon.config.api.enabled = True

        async def boom():
            raise OSError("port in use")

        lifecycle_daemon._start_api_server = boom
        with pytest.raises(OSError):
            await lifecycle_daemon.start()
        lifecycle_daemon._interceptor.stop.assert_called()

    def test_invalid_policy_reload_keeps_current_rules(self, lifecycle_daemon, policy_file):
        before = len(lifecycle_daemon.policy_engine.policy.rules)
        with open(policy_file, "w") as f:
            f.write("rules:\n  - match: {vendor: '046d'}\n    action: allow\n")

        assert lifecycle_daemon.reload_policy() is False
        assert len(lifecycle_daemon.policy_engine.policy.rules) == before

    def test_sighup_reloads_policy(self, lifecycle_daemon, policy_file):
        import signal

        _ = lifecycle_daemon.policy_engine
        with open(policy_file, "w") as f:
            f.write("rules:\n  - match: '*'\n    action: block\n")

        lifecycle_daemon.handle_signal(signal.SIGHUP)
        assert len(lifecycle_daemon.policy_engine.policy.rules) == 1
        assert not lifecycle_daemon._shutdown_event.is_set()  # reload, not shutdown


class TestAlerts:
    @pytest.mark.asyncio
    async def test_webhook_receives_block_alert(self, config, attack_descriptor):
        import http.server
        import json
        import threading

        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers["Content-Length"])
                received.append(json.loads(self.rfile.read(length)))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        config.alerts.enabled = True
        config.alerts.methods.webhook = f"http://127.0.0.1:{server.server_port}/hook"
        d = SentinelDaemon(config)
        d._interceptor = MagicMock()

        await d.handle_device_event(_make_event(attack_descriptor))
        thread.join(timeout=5)
        server.server_close()

        assert len(received) == 1
        assert received[0]["event"] == "device_blocked"
        assert received[0]["vid"] == "dead"


class TestFailureExit:
    @pytest.mark.asyncio
    async def test_loop_error_exits_nonzero_and_cleans_up(self, config, work_dir):
        """systemd only restarts on failure, so an event-loop crash must not exit 0."""
        from sentinel.daemon import run_daemon

        config.daemon.pid_file = os.path.join(work_dir, "sentinel.pid")
        config.daemon.log_file = None
        config.policy.hot_reload = False

        interceptor = MagicMock()
        interceptor.start.return_value = []

        async def broken_events():
            raise OSError("netlink socket closed")
            yield

        interceptor.events = broken_events

        from unittest.mock import patch

        with patch("sentinel.daemon.get_platform_interceptor", return_value=interceptor):
            assert await run_daemon(config) == 1
        interceptor.stop.assert_called()
        assert not os.path.exists(config.daemon.pid_file)


class TestHeldDeviceReplug:
    @pytest.mark.asyncio
    async def test_held_device_still_first_seen(self, work_dir, config):
        """A held device must not skip `first_seen` review rules when re-plugged."""
        policy_path = os.path.join(work_dir, "held.yaml")
        with open(policy_path, "w") as f:
            f.write(
                "rules:\n"
                "  - match: {first_seen: true, class: HID}\n"
                "    action: review\n"
                "  - match: {class: Audio}\n"
                "    action: allow\n"
                "  - match: '*'\n"
                "    action: review\n"
            )
        config.policy.rules_file = policy_path
        d = SentinelDaemon(config)
        d._interceptor = MagicMock()

        # HID + audio, no manufacturer: held on first plug
        device = create_test_descriptor(
            vid="4444", pid="5555", manufacturer=None, interfaces=[(0x03, 1, 1), (0x01, 1, 0)]
        )
        first = await d.handle_device_event(_make_event(device))
        second = await d.handle_device_event(_make_event(device))

        assert first["action"] == "review"
        assert second["action"] == "review"
