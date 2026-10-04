"""
Linux sysfs access for USB devices.

Reads device descriptors from the kernel's cached copy in sysfs instead of
talking to the device. This works for devices that are not yet authorized
(no driver bound), needs no libusb, and never sends a request to a device
that may be hostile.

Also controls the per-device ``authorized`` flag and the per-bus
``authorized_default`` flag that keeps new devices unbound until a verdict
is reached.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
)

logger = logging.getLogger(__name__)

SYSFS_USB_DEVICES = Path("/sys/bus/usb/devices")

# USB descriptor types (USB 2.0 spec, table 9-5)
_DT_DEVICE = 0x01
_DT_CONFIG = 0x02
_DT_INTERFACE = 0x04
_DT_ENDPOINT = 0x05

# sysfs `speed` attribute (Mb/s) -> DeviceDescriptor.speed
_SPEEDS = {
    "1.5": "low",
    "12": "full",
    "480": "high",
    "5000": "super",
    "10000": "super_plus",
    "20000": "super_plus",
}


class SysfsReadError(Exception):
    """A device's sysfs entry is missing or unreadable."""


def parse_interfaces(raw: bytes) -> list[InterfaceDescriptor]:
    """
    Parse interface and endpoint descriptors from a raw descriptor blob.

    ``raw`` is the content of a device's sysfs ``descriptors`` file: the
    18-byte device descriptor followed by every configuration's full
    descriptor set. Interfaces from all configurations and alternate
    settings are returned, so a device cannot hide a class behind a
    configuration the host has not selected yet. Class-specific and
    unknown descriptors are skipped; a truncated blob ends parsing.
    """
    interfaces: list[InterfaceDescriptor] = []
    current: InterfaceDescriptor | None = None
    pos = 0

    while pos + 2 <= len(raw):
        length = raw[pos]
        dtype = raw[pos + 1]
        if length < 2 or pos + length > len(raw):
            break
        desc = raw[pos : pos + length]

        if dtype == _DT_INTERFACE and length >= 9:
            current = InterfaceDescriptor(
                interface_number=desc[2],
                alternate_setting=desc[3],
                num_endpoints=desc[4],
                interface_class=desc[5],
                interface_subclass=desc[6],
                interface_protocol=desc[7],
            )
            interfaces.append(current)
        elif dtype == _DT_ENDPOINT and length >= 7 and current is not None:
            current.endpoints.append(
                EndpointDescriptor(
                    address=desc[2],
                    attributes=desc[3],
                    max_packet_size=int.from_bytes(desc[4:6], "little"),
                    interval=desc[6],
                )
            )
        elif dtype == _DT_CONFIG:
            current = None

        pos += length

    return interfaces


def _read_attr(path: Path, name: str) -> str | None:
    try:
        return (path / name).read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as e:
        logger.debug("Cannot read %s/%s: %s", path, name, e)
        return None


def _read_int(path: Path, name: str, base: int = 10) -> int | None:
    value = _read_attr(path, name)
    if value is None:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def read_device(sys_path: str | Path) -> DeviceDescriptor:
    """
    Build a DeviceDescriptor from a USB device's sysfs directory.

    Args:
        sys_path: e.g. /sys/devices/pci0000:00/0000:00:14.0/usb1/1-2

    Raises:
        SysfsReadError: If the path is not a readable USB device
    """
    path = Path(sys_path)
    vid = _read_attr(path, "idVendor")
    pid = _read_attr(path, "idProduct")
    if not vid or not pid:
        raise SysfsReadError(f"Not a USB device (no idVendor/idProduct): {path}")

    try:
        raw = (path / "descriptors").read_bytes()
    except OSError as e:
        raise SysfsReadError(f"Cannot read descriptors for {path}: {e}") from e

    # `version` is bcdUSB rendered as " 2.00"
    bcd_usb = None
    version = _read_attr(path, "version")
    if version:
        try:
            major, minor = version.split(".")
            bcd_usb = (int(major) << 8) | int(minor, 16)
        except ValueError:
            pass

    return DeviceDescriptor(
        vid=vid.lower(),
        pid=pid.lower(),
        device_class=_read_int(path, "bDeviceClass", 16) or 0,
        device_subclass=_read_int(path, "bDeviceSubClass", 16) or 0,
        device_protocol=_read_int(path, "bDeviceProtocol", 16) or 0,
        manufacturer=_read_attr(path, "manufacturer") or None,
        product=_read_attr(path, "product") or None,
        serial=_read_attr(path, "serial") or None,
        interfaces=parse_interfaces(raw),
        bus=_read_int(path, "busnum"),
        address=_read_int(path, "devnum"),
        speed=_SPEEDS.get(_read_attr(path, "speed") or ""),
        bcd_usb=bcd_usb,
        bcd_device=_read_int(path, "bcdDevice", 16),
    )


def iter_devices(root: Path = SYSFS_USB_DEVICES) -> Iterator[Path]:
    """Yield resolved sysfs paths of USB devices, excluding root hubs and interfaces."""
    if not root.is_dir():
        return
    for entry in sorted(root.iterdir()):
        # "usbN" are root hubs; "1-2:1.0" are interfaces
        if entry.name.startswith("usb") or ":" in entry.name:
            continue
        yield entry.resolve()


def iter_root_hubs(root: Path = SYSFS_USB_DEVICES) -> Iterator[Path]:
    """Yield resolved sysfs paths of root hubs (one per USB bus)."""
    if not root.is_dir():
        return
    for entry in sorted(root.iterdir()):
        if entry.name.startswith("usb"):
            yield entry.resolve()


def is_authorized(sys_path: str | Path) -> bool | None:
    """Return the device's ``authorized`` flag, or None if unreadable."""
    value = _read_attr(Path(sys_path), "authorized")
    if value is None:
        return None
    return value == "1"


def set_authorized(sys_path: str | Path, authorized: bool) -> bool:
    """
    Authorize (bind drivers) or deauthorize (unbind) a device.

    Returns:
        True on success. Failure is logged, never raised: the caller is
        handling a live device event and must keep running.
    """
    auth_file = Path(sys_path) / "authorized"
    try:
        auth_file.write_text("1" if authorized else "0")
        return True
    except OSError as e:
        logger.error(
            "Failed to %s %s: %s",
            "authorize" if authorized else "deauthorize",
            sys_path,
            e,
        )
        return False


class DefaultDenyGuard:
    """
    Make the kernel leave newly attached devices unauthorized.

    Writes 0 to every root hub's ``authorized_default`` so new devices are
    enumerated (descriptors readable) but no driver binds until the daemon
    authorizes them. Devices already attached are unaffected. ``release()``
    restores the previous values.

    If the daemon dies without releasing, new devices stay unauthorized
    until it restarts: the guard fails closed.
    """

    def __init__(self, root: Path = SYSFS_USB_DEVICES) -> None:
        self.root = root
        self._saved: dict[Path, str] = {}

    @property
    def active(self) -> bool:
        return bool(self._saved)

    def engage(self) -> int:
        """Set authorized_default=0 on all root hubs. Returns hubs changed."""
        for hub in iter_root_hubs(self.root):
            self.engage_hub(hub)
        return len(self._saved)

    def engage_hub(self, hub: Path) -> bool:
        """
        Set authorized_default=0 on one root hub.

        Also used for buses that appear later (a new host controller, e.g.
        a Thunderbolt dock), which the kernel creates with the default 1.
        """
        hub = hub.resolve()
        if hub in self._saved:
            return True
        current = _read_attr(hub, "authorized_default")
        if current is None:
            return False
        try:
            (hub / "authorized_default").write_text("0")
        except OSError as e:
            logger.error("Cannot set %s/authorized_default: %s", hub, e)
            return False
        self._saved[hub] = current
        return True

    def release(self) -> None:
        """Restore each root hub's original authorized_default."""
        for hub, value in self._saved.items():
            try:
                (hub / "authorized_default").write_text(value)
            except OSError as e:
                logger.error("Cannot restore %s/authorized_default: %s", hub, e)
        self._saved.clear()
