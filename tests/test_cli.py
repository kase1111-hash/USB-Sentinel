"""
Tests for the usb-sentinel command line, run against a fake sysfs tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.cli import main
from sentinel.interceptor import sysfs
from sentinel.policy.fingerprint import generate_fingerprint
from tests.test_sysfs import BADUSB, KEYBOARD, make_device

SHIPPED_POLICY = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"

# HID keyboard with no manufacturer string: held for review by the daemon
ANONYMOUS_KEYBOARD = KEYBOARD.replace(b"\x6d\x04\x1c\xc3", b"\x34\x12\x78\x56", 1)


@pytest.fixture
def sys_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "bus_usb_devices"
    root.mkdir()
    monkeypatch.setattr(sysfs, "SYSFS_USB_DEVICES", root)
    return root


@pytest.fixture
def config_file(tmp_path: Path) -> str:
    path = tmp_path / "sentinel.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "daemon": {"pid_file": str(tmp_path / "sentinel.pid"), "log_file": None},
                "policy": {"rules_file": str(SHIPPED_POLICY)},
                "database": {"path": str(tmp_path / "audit.db")},
                "analyzer": {"enabled": False},
            }
        )
    )
    return str(path)


def run(config_file: str, *args: str) -> int:
    return main(["-c", config_file, *args])


class TestPolicyCommands:
    def test_policy_test(self, config_file, capsys):
        """Used to crash with a TypeError building the test descriptor."""
        assert run(config_file, "policy", "test", "1a86", "7523") == 0
        assert "BLOCK" in capsys.readouterr().out

    def test_policy_test_with_strings_and_class(self, config_file, capsys):
        args = ["policy", "test", "abcd", "0001", "--class", "HID", "--product", "Rubber Ducky"]
        assert run(config_file, *args) == 0
        assert "Known attack device signature" in capsys.readouterr().out

    def test_validate_rejects_bad_policy(self, config_file, tmp_path, capsys):
        bad = tmp_path / "policy.yaml"
        bad.write_text("rules:\n  - match: {vendor: '046d'}\n    action: allow\n")
        config = yaml.safe_load(Path(config_file).read_text())
        config["policy"]["rules_file"] = str(bad)
        Path(config_file).write_text(yaml.safe_dump(config))

        assert run(config_file, "policy", "validate") == 1
        assert "Unknown match key" in capsys.readouterr().out

    def test_reload_without_daemon(self, config_file, capsys):
        assert run(config_file, "policy", "reload") == 1
        assert "not running" in capsys.readouterr().out


class TestScan:
    def test_scan_reports_decisions_without_changing_devices(self, config_file, sys_root, capsys):
        good = make_device(sys_root, "1-1", KEYBOARD)
        bad = make_device(sys_root, "1-2", BADUSB, product="Storage Keyboard")

        assert run(config_file, "scan") == 0
        out = capsys.readouterr().out

        lines = {line.split()[0]: line for line in out.splitlines() if line.startswith("1-")}
        assert " allow " in lines["1-1"]
        assert " block " in lines["1-2"]
        assert sysfs.is_authorized(good) is True
        assert sysfs.is_authorized(bad) is True  # scan never enforces

    def test_scan_with_no_devices(self, config_file, sys_root):
        assert run(config_file, "scan") == 1


class TestTrustWorkflow:
    def test_trusting_held_device_authorizes_it_now(self, config_file, sys_root, capsys):
        """The workflow the daemon's HELD log line tells operators to use."""
        import asyncio
        from unittest.mock import MagicMock

        from sentinel.config import load_config
        from sentinel.daemon import SentinelDaemon
        from sentinel.interceptor.linux import EventType, USBEvent

        path = make_device(sys_root, "1-3", ANONYMOUS_KEYBOARD, manufacturer=None, authorized="0")
        descriptor = sysfs.read_device(path)

        daemon = SentinelDaemon(load_config(config_file))
        daemon._interceptor = MagicMock()
        result = asyncio.run(
            daemon.handle_device_event(
                USBEvent(EventType.ADD, 1, 7, "", str(path), descriptor=descriptor)
            )
        )
        daemon.db.close()
        assert result["action"] == "review"
        assert result["fingerprint"] == generate_fingerprint(descriptor)

        assert run(config_file, "status") == 0
        assert "Held (review):  1" in capsys.readouterr().out

        assert run(config_file, "events", "-t", "reviewed") == 0
        assert "reviewed" in capsys.readouterr().out

        assert run(config_file, "devices", "trust", result["fingerprint"], "trusted") == 0
        assert "Authorized attached device: 1-3" in capsys.readouterr().out
        assert sysfs.is_authorized(path) is True

        assert run(config_file, "devices", "trust", result["fingerprint"], "blocked") == 0
        assert sysfs.is_authorized(path) is False

    def test_trust_for_detached_device(self, config_file, sys_root, capsys):
        from sentinel.audit.database import AuditDatabase
        from sentinel.config import load_config

        db = AuditDatabase(load_config(config_file).database.path)
        db.add_device(fingerprint="feedfacecafebeef", vid="1234", pid="5678")
        db.close()

        assert run(config_file, "devices", "trust", "feedfacecafebeef", "trusted") == 0
        assert "next time the device is plugged in" in capsys.readouterr().out
