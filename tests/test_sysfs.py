"""
Tests for reading devices from sysfs and enforcing verdicts there.

Uses a fake /sys/bus/usb/devices tree with real descriptor byte layouts.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sentinel.interceptor import sysfs
from sentinel.interceptor.linux import EventType, USBEvent, USBInterceptor


def device_descriptor(vid: int, pid: int, device_class: int = 0) -> bytes:
    return struct.pack(
        "<BBHBBBBHHHBBBB", 18, 1, 0x0200, device_class, 0, 0, 64, vid, pid, 0x0110, 1, 2, 3, 1
    )


def config_descriptor(total_length: int, num_interfaces: int) -> bytes:
    return struct.pack("<BBHBBBBB", 9, 2, total_length, num_interfaces, 1, 0, 0xA0, 50)


def interface(number: int, alt: int, num_eps: int, cls: int, sub: int, proto: int) -> bytes:
    return bytes([9, 4, number, alt, num_eps, cls, sub, proto, 0])


def endpoint(address: int, attributes: int, max_packet: int, interval: int) -> bytes:
    return struct.pack("<BBBBHB", 7, 5, address, attributes, max_packet, interval)


def hid_class_descriptor() -> bytes:
    return bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0])


def build(vid: int, pid: int, *body: bytes, device_class: int = 0) -> bytes:
    payload = b"".join(body)
    num_interfaces = len({b[2] for b in body if len(b) == 9 and b[1] == 4})
    return (
        device_descriptor(vid, pid, device_class)
        + config_descriptor(9 + len(payload), num_interfaces)
        + payload
    )


KEYBOARD = build(
    0x046D,
    0xC31C,
    interface(0, 0, 1, 0x03, 0x01, 0x01),
    hid_class_descriptor(),
    endpoint(0x81, 0x03, 8, 10),
)

# HID keyboard + mass storage, the classic BadUSB shape
BADUSB = build(
    0x1234,
    0x5678,
    interface(0, 0, 1, 0x03, 0x01, 0x01),
    hid_class_descriptor(),
    endpoint(0x81, 0x03, 8, 10),
    interface(1, 0, 2, 0x08, 0x06, 0x50),
    endpoint(0x82, 0x02, 512, 0),
    endpoint(0x02, 0x02, 512, 0),
)


def make_device(
    root: Path,
    name: str,
    raw: bytes,
    *,
    authorized: str = "1",
    manufacturer: str | None = "Logitech",
    product: str | None = "USB Keyboard",
) -> Path:
    """Create /sys/devices/.../<name> and the /sys/bus/usb/devices symlink."""
    real = root.parent / "devices" / name
    real.mkdir(parents=True)
    vid, pid = struct.unpack_from("<HH", raw, 8)
    attrs = {
        "idVendor": f"{vid:04x}\n",
        "idProduct": f"{pid:04x}\n",
        "bDeviceClass": f"{raw[4]:02x}\n",
        "bDeviceSubClass": "00\n",
        "bDeviceProtocol": "00\n",
        "bcdDevice": "0110\n",
        "version": " 2.00\n",
        "speed": "12\n",
        "busnum": "1\n",
        "devnum": "7\n",
        "authorized": f"{authorized}\n",
    }
    if manufacturer is not None:
        attrs["manufacturer"] = manufacturer + "\n"
    if product is not None:
        attrs["product"] = product + "\n"
    for key, value in attrs.items():
        (real / key).write_text(value)
    (real / "descriptors").write_bytes(raw)
    (root / name).symlink_to(real)
    return real


@pytest.fixture
def sys_root(tmp_path: Path) -> Path:
    root = tmp_path / "bus_usb_devices"
    root.mkdir()
    for bus in ("usb1", "usb2"):
        hub = tmp_path / "devices" / bus
        hub.mkdir(parents=True)
        (hub / "authorized_default").write_text("1\n")
        (root / bus).symlink_to(hub)
    return root


class TestParseInterfaces:
    def test_keyboard(self) -> None:
        interfaces = sysfs.parse_interfaces(KEYBOARD)

        assert len(interfaces) == 1
        kbd = interfaces[0]
        assert kbd.is_keyboard
        assert kbd.num_endpoints == 1
        assert kbd.endpoints[0].address == 0x81
        assert kbd.endpoints[0].is_interrupt

    def test_composite_with_class_specific_descriptors(self) -> None:
        interfaces = sysfs.parse_interfaces(BADUSB)

        assert [i.interface_class for i in interfaces] == [0x03, 0x08]
        assert [len(i.endpoints) for i in interfaces] == [1, 2]
        assert interfaces[1].endpoints[0].max_packet_size == 512

    def test_all_alternate_settings_and_configurations_are_included(self) -> None:
        """A device must not be able to hide a class in a second configuration."""
        second_config = config_descriptor(9 + 9 + 7, 1) + interface(0, 0, 1, 0x03, 1, 1)
        second_config += endpoint(0x81, 0x03, 8, 10)
        raw = (
            build(0x1234, 0x0001, interface(0, 0, 0, 0x0E, 2, 0), interface(0, 1, 1, 0x0E, 2, 0))
            + second_config
        )
        interfaces = sysfs.parse_interfaces(raw)

        assert [(i.interface_class, i.alternate_setting) for i in interfaces] == [
            (0x0E, 0),
            (0x0E, 1),
            (0x03, 0),
        ]

    @pytest.mark.parametrize("cut", [1, 18, 20, len(KEYBOARD) - 3])
    def test_truncated_blob_does_not_raise(self, cut: int) -> None:
        sysfs.parse_interfaces(KEYBOARD[:cut])

    def test_zero_length_descriptor_stops_parsing(self) -> None:
        assert sysfs.parse_interfaces(device_descriptor(1, 2) + b"\x00\x04" * 10) == []


class TestReadDevice:
    def test_reads_attributes_and_descriptors(self, sys_root: Path) -> None:
        path = make_device(sys_root, "1-2", KEYBOARD)
        device = sysfs.read_device(path)

        assert device.vid_pid == "046d:c31c"
        assert device.manufacturer == "Logitech"
        assert device.product == "USB Keyboard"
        assert device.serial is None
        assert device.has_keyboard
        assert (device.bus, device.address, device.speed) == (1, 7, "full")
        assert device.bcd_usb == 0x0200
        assert device.bcd_device == 0x0110

    def test_missing_strings_are_none(self, sys_root: Path) -> None:
        path = make_device(sys_root, "1-3", KEYBOARD, manufacturer=None, product=None)
        device = sysfs.read_device(path)

        assert device.manufacturer is None
        assert device.product is None

    def test_not_a_device(self, tmp_path: Path) -> None:
        with pytest.raises(sysfs.SysfsReadError):
            sysfs.read_device(tmp_path)

    def test_iter_devices_skips_root_hubs_and_interfaces(self, sys_root: Path) -> None:
        make_device(sys_root, "1-2", KEYBOARD)
        (sys_root / "1-2:1.0").symlink_to(sys_root / "1-2")

        assert [p.name for p in sysfs.iter_devices(sys_root)] == ["1-2"]


class TestDefaultDenyGuard:
    def test_engage_and_release_restore_previous_values(self, sys_root: Path) -> None:
        (sys_root / "usb2" / "authorized_default").write_text("2\n")
        guard = sysfs.DefaultDenyGuard(sys_root)

        assert guard.engage() == 2
        assert (sys_root / "usb1" / "authorized_default").read_text() == "0"
        assert (sys_root / "usb2" / "authorized_default").read_text() == "0"

        guard.release()
        assert not guard.active
        assert (sys_root / "usb1" / "authorized_default").read_text() == "1"
        assert (sys_root / "usb2" / "authorized_default").read_text() == "2"

    def test_new_bus_is_covered(self, sys_root: Path, tmp_path: Path) -> None:
        guard = sysfs.DefaultDenyGuard(sys_root)
        guard.engage()

        dock = tmp_path / "devices" / "usb3"
        dock.mkdir()
        (dock / "authorized_default").write_text("1\n")
        assert guard.engage_hub(dock)
        assert (dock / "authorized_default").read_text() == "0"

        guard.release()
        assert (dock / "authorized_default").read_text() == "1"


class TestInterceptorEnforcement:
    def test_start_engages_guard_and_reports_pending(self, sys_root: Path) -> None:
        make_device(sys_root, "1-1", KEYBOARD, authorized="1")
        make_device(sys_root, "1-2", BADUSB, authorized="0")
        interceptor = USBInterceptor(sysfs_root=sys_root)
        interceptor.monitor.start = lambda: None  # no netlink in tests

        pending = interceptor.start()

        assert interceptor.default_deny_active
        assert [Path(e.sys_path).name for e in pending] == ["1-2"]
        assert pending[0].event_type == EventType.ADD
        assert pending[0].descriptor.has_storage

        interceptor.stop()
        assert not interceptor.default_deny_active
        assert (sys_root / "usb1" / "authorized_default").read_text() == "1"

    def test_start_without_blocking_leaves_default(self, sys_root: Path) -> None:
        interceptor = USBInterceptor(block_during_analysis=False, sysfs_root=sys_root)
        interceptor.monitor.start = lambda: None
        interceptor.start()

        assert not interceptor.default_deny_active
        assert (sys_root / "usb1" / "authorized_default").read_text() == "1\n"

    def test_allow_and_block_write_authorized_flag(self, sys_root: Path) -> None:
        path = make_device(sys_root, "1-4", KEYBOARD, authorized="0")
        event = USBEvent(EventType.ADD, 1, 7, "", str(path))
        interceptor = USBInterceptor(sysfs_root=sys_root)

        assert interceptor.allow_device(event)
        assert sysfs.is_authorized(path) is True
        assert interceptor.block_device(event)
        assert sysfs.is_authorized(path) is False

    def test_enforcement_failure_is_reported_not_raised(self, tmp_path: Path) -> None:
        event = USBEvent(EventType.ADD, 1, 7, "", str(tmp_path / "gone"))
        assert USBInterceptor(sysfs_root=tmp_path).allow_device(event) is False


class FakeUdevDevice:
    def __init__(self, action: str, sys_path: Path, **props: str) -> None:
        self.action = action
        self.sys_path = str(sys_path)
        self.device_node = None
        self._props = {"BUSNUM": "001", "DEVNUM": "007", **props}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._props.get(key, default)


class FakeNetlinkMonitor:
    """Stands in for pyudev.Monitor: a readable fd plus poll(timeout=0)."""

    def __init__(self) -> None:
        import os

        self._r, self._w = os.pipe()
        self._queue: list[FakeUdevDevice] = []

    def fileno(self) -> int:
        return self._r

    def start(self) -> None:
        pass

    def push(self, device: FakeUdevDevice) -> None:
        import os

        self._queue.append(device)
        os.write(self._w, b"x")

    def poll(self, timeout: float | None = None) -> FakeUdevDevice | None:
        import os

        if not self._queue:
            return None
        os.read(self._r, 1)
        return self._queue.pop(0)


class TestEventMonitoring:
    async def _collect(self, interceptor: USBInterceptor, count: int) -> list[USBEvent]:
        import asyncio

        events: list[USBEvent] = []

        async def consume() -> None:
            async for event in interceptor.events():
                events.append(event)
                if len(events) == count:
                    interceptor.monitor.stop()
                    return

        await asyncio.wait_for(consume(), timeout=5)
        return events

    async def test_events_flow_through_event_loop(self, sys_root: Path) -> None:
        path = make_device(sys_root, "1-5", BADUSB, authorized="0")
        fake = FakeNetlinkMonitor()
        interceptor = USBInterceptor(sysfs_root=sys_root)
        interceptor.monitor._monitor = fake

        fake.push(FakeUdevDevice("add", path, PRODUCT="1234/5678/110"))
        fake.push(FakeUdevDevice("bind", path))
        fake.push(FakeUdevDevice("remove", path, PRODUCT="1234/5678/110"))

        events = await self._collect(interceptor, 3)

        assert [e.event_type for e in events] == [EventType.ADD, EventType.BIND, EventType.REMOVE]
        add = events[0]
        assert add.descriptor is not None and add.descriptor.has_hid and add.descriptor.has_storage
        assert (add.vid, add.pid) == ("1234", "5678")
        assert events[2].descriptor is None
        assert (events[2].vid, events[2].pid) == ("1234", "5678")

    async def test_new_root_hub_is_locked_down_not_evaluated(
        self, sys_root: Path, tmp_path: Path
    ) -> None:
        interceptor = USBInterceptor(sysfs_root=sys_root)
        interceptor.monitor.start = lambda: None
        interceptor.start()

        dock = tmp_path / "devices" / "usb3"
        dock.mkdir()
        (dock / "authorized_default").write_text("1\n")
        device = make_device(sys_root, "3-1", KEYBOARD, authorized="0")

        fake = FakeNetlinkMonitor()
        interceptor.monitor._monitor = fake
        interceptor.monitor._running = True
        fake.push(FakeUdevDevice("add", dock))
        fake.push(FakeUdevDevice("add", device))

        events = await self._collect(interceptor, 1)

        assert [Path(e.sys_path).name for e in events] == ["3-1"]
        assert (dock / "authorized_default").read_text() == "0"
        interceptor.stop()
        assert (dock / "authorized_default").read_text() == "1"


def test_release_tolerates_removed_bus(sys_root: Path, tmp_path: Path, caplog) -> None:
    guard = sysfs.DefaultDenyGuard(sys_root)
    dock = tmp_path / "devices" / "usb9"
    dock.mkdir()
    (dock / "authorized_default").write_text("1\n")
    guard.engage()
    guard.engage_hub(dock)

    import shutil

    shutil.rmtree(dock)
    guard.release()

    assert "Cannot restore" not in caplog.text
    assert (sys_root / "usb1" / "authorized_default").read_text() == "1"
