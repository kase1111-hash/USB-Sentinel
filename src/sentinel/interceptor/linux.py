"""
Linux USB Event Interceptor.

Captures USB device events with pyudev, reads descriptors from sysfs, and
enforces verdicts through the kernel's USB authorization flags.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import usb.core
import usb.util

from sentinel.interceptor import sysfs
from sentinel.interceptor.descriptors import DeviceDescriptor, extract_device_info

logger = logging.getLogger(__name__)


class EventType(Enum):
    """USB device event types."""

    ADD = "add"
    REMOVE = "remove"
    BIND = "bind"
    UNBIND = "unbind"


@dataclass
class USBEvent:
    """USB device event."""

    event_type: EventType
    bus: int
    address: int
    device_path: str
    sys_path: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    descriptor: DeviceDescriptor | None = None
    vid: str | None = None
    pid: str | None = None

    @property
    def device_id(self) -> str:
        """Get unique device identifier (bus:address)."""
        return f"{self.bus}:{self.address}"


class USBEnumerator:
    """
    USB device enumerator using PyUSB.

    Provides static enumeration of currently connected devices.
    """

    def __init__(self) -> None:
        self._backend = None

    def enumerate_all(self) -> list[DeviceDescriptor]:
        """
        Enumerate all currently connected USB devices.

        Returns:
            List of DeviceDescriptor for each connected device.
        """
        devices = []
        try:
            for dev in usb.core.find(find_all=True):
                try:
                    descriptor = extract_device_info(dev)
                    devices.append(descriptor)
                except usb.core.USBError as e:
                    logger.warning(
                        "Failed to read device %04x:%04x: %s", dev.idVendor, dev.idProduct, e
                    )
                except Exception as e:
                    logger.error("Error extracting device info: %s", e)
        except usb.core.NoBackendError:
            logger.error("No USB backend available. Install libusb.")
            raise
        return devices

    def find_device(self, bus: int, address: int) -> DeviceDescriptor | None:
        """
        Find a specific device by bus and address.

        Args:
            bus: USB bus number
            address: Device address on bus

        Returns:
            DeviceDescriptor if found, None otherwise.
        """
        dev = usb.core.find(bus=bus, address=address)
        if dev is None:
            return None
        try:
            return extract_device_info(dev)
        except usb.core.USBError as e:
            logger.warning("Failed to read device at %d:%d: %s", bus, address, e)
            return None

    def find_by_vid_pid(self, vid: int, pid: int) -> list[DeviceDescriptor]:
        """
        Find all devices matching VID:PID.

        Args:
            vid: Vendor ID
            pid: Product ID

        Returns:
            List of matching DeviceDescriptor objects.
        """
        devices = []
        for dev in usb.core.find(find_all=True, idVendor=vid, idProduct=pid):
            with contextlib.suppress(usb.core.USBError):
                devices.append(extract_device_info(dev))
        return devices


class USBMonitor:
    """
    USB device event monitor using pyudev.

    Events are read from the netlink socket via the asyncio event loop, so
    waiting for USB events never blocks other tasks (such as the API server).
    """

    def __init__(self) -> None:
        self._context: Any = None
        self._monitor: Any = None
        self._running = False
        self._enumerator = USBEnumerator()
        # Called as soon as a root hub (new bus) is read off the socket,
        # before queued device events are processed.
        self.on_new_bus: Callable[[Path], None] | None = None

    def _ensure_context(self) -> None:
        """Initialize pyudev context if needed."""
        if self._context is None:
            import pyudev

            self._context = pyudev.Context()

    def _ensure_monitor(self) -> None:
        """Initialize pyudev monitor if needed."""
        if self._monitor is None:
            import pyudev

            self._ensure_context()
            self._monitor = pyudev.Monitor.from_netlink(self._context)
            self._monitor.filter_by(subsystem="usb", device_type="usb_device")

    def start(self) -> None:
        """
        Start receiving kernel events.

        Events are buffered from this point, so call it before scanning
        sysfs for existing devices to avoid missing a device in between.
        """
        self._ensure_monitor()
        self._monitor.start()
        self._running = True

    def _read_descriptor(self, sys_path: str, bus: int, address: int) -> DeviceDescriptor | None:
        """Read descriptors from sysfs, falling back to libusb."""
        try:
            return sysfs.read_device(sys_path)
        except sysfs.SysfsReadError as e:
            logger.debug("sysfs read failed (%s), trying libusb", e)
        try:
            return self._enumerator.find_device(bus, address)
        except Exception as e:
            logger.warning("Could not read descriptors for %s: %s", sys_path, e)
            return None

    def _parse_udev_event(self, device: Any) -> USBEvent | None:
        """
        Parse a pyudev device into a USBEvent.

        Args:
            device: pyudev.Device object

        Returns:
            USBEvent or None if parsing fails.
        """
        try:
            # Get event type
            action = device.action
            if action not in ("add", "remove", "bind", "unbind"):
                return None
            event_type = EventType(action)

            # Extract bus and address
            bus_num = device.get("BUSNUM")
            dev_num = device.get("DEVNUM")

            if bus_num is None or dev_num is None:
                return None

            bus = int(bus_num)
            address = int(dev_num)

            # VID/PID from udev properties; PRODUCT ("46d/c52b/1200") is
            # set by the kernel, ID_* only once udev has processed the device
            vid = device.get("ID_VENDOR_ID")
            pid = device.get("ID_MODEL_ID")
            product = device.get("PRODUCT")
            if (vid is None or pid is None) and product:
                parts = product.split("/")
                if len(parts) >= 2:
                    vid, pid = parts[0].zfill(4), parts[1].zfill(4)

            event = USBEvent(
                event_type=event_type,
                bus=bus,
                address=address,
                device_path=device.device_node or "",
                sys_path=device.sys_path,
                vid=vid,
                pid=pid,
            )

            if event_type == EventType.ADD:
                event.descriptor = self._read_descriptor(device.sys_path, bus, address)

            return event

        except Exception as e:
            logger.error("Error parsing udev event: %s", e)
            return None

    async def monitor_events(self) -> AsyncIterator[USBEvent]:
        """
        Asynchronously monitor USB events.

        Yields:
            USBEvent for each device add/remove/bind/unbind event.
        """
        if not self._running:
            self.start()
        assert self._monitor is not None

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[USBEvent] = asyncio.Queue()

        def on_readable() -> None:
            # Drain everything the socket has; never raise into the loop.
            while True:
                try:
                    device = self._monitor.poll(timeout=0)
                except Exception as e:
                    logger.error("udev monitor read failed: %s", e)
                    return
                if device is None:
                    return
                event = self._parse_udev_event(device)
                if event is None:
                    continue
                if (
                    event.event_type == EventType.ADD
                    and Path(event.sys_path).name.startswith("usb")
                    and self.on_new_bus is not None
                ):
                    try:
                        self.on_new_bus(Path(event.sys_path))
                    except Exception as e:
                        logger.error("Failed to protect new bus %s: %s", event.sys_path, e)
                queue.put_nowait(event)

        fd = self._monitor.fileno()
        loop.add_reader(fd, on_readable)
        logger.info("Starting USB event monitor")

        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                logger.debug(
                    "USB event: %s %s (VID=%s PID=%s)",
                    event.event_type.value,
                    event.device_id,
                    event.vid,
                    event.pid,
                )
                yield event
        finally:
            loop.remove_reader(fd)
            self._running = False
            logger.info("USB event monitor stopped")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False


class DeviceAuthorizer:
    """
    USB device authorization controller.

    Controls whether devices are allowed to bind to drivers
    using the sysfs authorized attribute.
    """

    SYSFS_USB_PATH = Path("/sys/bus/usb/devices")

    def __init__(self) -> None:
        self._check_permissions()

    def _check_permissions(self) -> None:
        """Check if we have permission to control device authorization."""
        if os.geteuid() != 0:
            logger.warning("Not running as root. Device authorization control may not work.")

    def _get_device_path(self, bus: int, address: int) -> Path | None:
        """
        Find sysfs path for a device.

        Args:
            bus: USB bus number
            address: Device address

        Returns:
            Path to device in sysfs, or None if not found.
        """
        # USB devices are named like "1-1" or "1-1.2" in sysfs
        # We need to search for the device with matching bus/address
        for device_dir in self.SYSFS_USB_PATH.iterdir():
            if device_dir.name.startswith("usb"):
                continue  # Skip controller directories

            busnum_file = device_dir / "busnum"
            devnum_file = device_dir / "devnum"

            if busnum_file.exists() and devnum_file.exists():
                try:
                    current_bus = int(busnum_file.read_text().strip())
                    current_addr = int(devnum_file.read_text().strip())
                    if current_bus == bus and current_addr == address:
                        return device_dir
                except (OSError, ValueError):
                    continue
        return None

    def _get_device_path_by_syspath(self, sys_path: str) -> Path | None:
        """Get device path from sysfs path."""
        path = Path(sys_path)
        if path.exists():
            return path
        return None

    def is_authorized(self, bus: int, address: int) -> bool | None:
        """
        Check if a device is authorized.

        Args:
            bus: USB bus number
            address: Device address

        Returns:
            True if authorized, False if not, None if unable to determine.
        """
        device_path = self._get_device_path(bus, address)
        if device_path is None:
            return None

        auth_file = device_path / "authorized"
        if not auth_file.exists():
            return None

        try:
            value = auth_file.read_text().strip()
            return value == "1"
        except OSError:
            return None

    def authorize(self, bus: int, address: int) -> bool:
        """
        Authorize a device (allow driver binding).

        Args:
            bus: USB bus number
            address: Device address

        Returns:
            True if successful, False otherwise.
        """
        return self._set_authorized(bus, address, True)

    def deauthorize(self, bus: int, address: int) -> bool:
        """
        Deauthorize a device (prevent driver binding).

        Args:
            bus: USB bus number
            address: Device address

        Returns:
            True if successful, False otherwise.
        """
        return self._set_authorized(bus, address, False)

    def _set_authorized(self, bus: int, address: int, authorized: bool) -> bool:
        """
        Set device authorization state.

        Args:
            bus: USB bus number
            address: Device address
            authorized: Whether to authorize

        Returns:
            True if successful, False otherwise.
        """
        device_path = self._get_device_path(bus, address)
        if device_path is None:
            logger.error("Device not found: %d:%d", bus, address)
            return False

        auth_file = device_path / "authorized"
        if not auth_file.exists():
            logger.error("No authorized file for device %d:%d", bus, address)
            return False

        try:
            auth_file.write_text("1" if authorized else "0")
            logger.info(
                "Device %d:%d %s", bus, address, "authorized" if authorized else "deauthorized"
            )
            return True
        except OSError as e:
            logger.error(
                "Failed to %s device %d:%d: %s",
                "authorize" if authorized else "deauthorize",
                bus,
                address,
                e,
            )
            return False

    def authorize_by_syspath(self, sys_path: str) -> bool:
        """Authorize device by sysfs path."""
        device_path = self._get_device_path_by_syspath(sys_path)
        if device_path is None:
            return False
        auth_file = device_path / "authorized"
        try:
            auth_file.write_text("1")
            return True
        except OSError:
            return False

    def deauthorize_by_syspath(self, sys_path: str) -> bool:
        """Deauthorize device by sysfs path."""
        device_path = self._get_device_path_by_syspath(sys_path)
        if device_path is None:
            return False
        auth_file = device_path / "authorized"
        try:
            auth_file.write_text("0")
            return True
        except OSError:
            return False


class USBInterceptor:
    """
    High-level USB interception interface.

    Combines monitoring, descriptor reading, and authorization control.

    With ``block_during_analysis`` the kernel is told to leave new devices
    unauthorized (no driver bound, so a keyboard cannot type) until
    ``allow_device()`` is called. Without it, devices work immediately and
    ``block_device()`` unbinds them after the fact.
    """

    def __init__(
        self,
        block_during_analysis: bool = True,
        analysis_timeout: float = 10.0,
        sysfs_root: Path | None = None,
        state_file: Path | None = None,
    ) -> None:
        """
        Initialize the interceptor.

        Args:
            block_during_analysis: Keep new devices unbound until a verdict
            analysis_timeout: Timeout for analysis in seconds
            sysfs_root: /sys/bus/usb/devices (overridable for tests)
        """
        self.enumerator = USBEnumerator()
        self.monitor = USBMonitor()
        self.authorizer = DeviceAuthorizer()
        self.block_during_analysis = block_during_analysis
        self.analysis_timeout = analysis_timeout
        self.sysfs_root = sysfs_root
        self._guard = sysfs.DefaultDenyGuard(sysfs_root, state_file)
        if block_during_analysis:
            self.monitor.on_new_bus = self._guard.engage_hub
        self._event_handlers: list[Callable[[USBEvent], None]] = []

    def add_event_handler(self, handler: Callable[[USBEvent], None]) -> None:
        """Add a handler for USB events."""
        self._event_handlers.append(handler)

    def remove_event_handler(self, handler: Callable[[USBEvent], None]) -> None:
        """Remove an event handler."""
        self._event_handlers.remove(handler)

    def enumerate_devices(self) -> list[DeviceDescriptor]:
        """Get all currently connected devices."""
        return self.enumerator.enumerate_all()

    @property
    def default_deny_active(self) -> bool:
        """True if new devices are being held unauthorized by the kernel."""
        return self._guard.active

    def start(self) -> list[USBEvent]:
        """
        Start intercepting.

        Returns:
            ADD events for attached devices that are waiting for a verdict
            (unauthorized), e.g. plugged in while the daemon was down.
        """
        self.monitor.start()
        if self.block_during_analysis:
            if self._guard.engage():
                logger.info("New USB devices stay unbound until they are evaluated")
            else:
                logger.warning(
                    "Could not set authorized_default on any USB bus (none found, or not "
                    "root); new devices will work before they are evaluated"
                )
        return self.pending_devices()

    def pending_devices(self) -> list[USBEvent]:
        """ADD events for attached devices whose authorized flag is 0."""
        events = []
        for path in sysfs.iter_devices(self.sysfs_root):
            if sysfs.is_authorized(path) is not False:
                continue
            try:
                descriptor = sysfs.read_device(path)
            except sysfs.SysfsReadError as e:
                logger.warning("Skipping unreadable device %s: %s", path, e)
                continue
            events.append(
                USBEvent(
                    event_type=EventType.ADD,
                    bus=descriptor.bus or 0,
                    address=descriptor.address or 0,
                    device_path="",
                    sys_path=str(path),
                    descriptor=descriptor,
                    vid=descriptor.vid,
                    pid=descriptor.pid,
                )
            )
        return events

    async def events(self) -> AsyncIterator[USBEvent]:
        """Async iterator for USB device events (root hubs are handled here)."""
        async for event in self.monitor.monitor_events():
            if Path(event.sys_path).name.startswith("usb"):
                # A root hub is a host controller appearing, not a device;
                # the monitor already locked its bus down (on_new_bus).
                continue

            yield event

            # Notify handlers
            for handler in self._event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error("Event handler error: %s", e)

    def allow_device(self, event: USBEvent) -> bool:
        """
        Authorize a device so drivers bind to it.

        Returns:
            True if device was authorized successfully.
        """
        if event.sys_path:
            if event.address and not sysfs.is_same_device(event.sys_path, event.bus, event.address):
                logger.warning(
                    "Not authorizing %s: the device there is no longer %d:%d",
                    event.sys_path,
                    event.bus,
                    event.address,
                )
                return False
            return sysfs.set_authorized(event.sys_path, True)
        return self.authorizer.authorize(event.bus, event.address)

    def block_device(self, event: USBEvent) -> bool:
        """
        Deauthorize a device (unbind drivers / keep them unbound).

        Returns:
            True if device was deauthorized successfully.
        """
        if event.sys_path:
            return sysfs.set_authorized(event.sys_path, False)
        return self.authorizer.deauthorize(event.bus, event.address)

    def stop(self, release: bool = True) -> None:
        """
        Stop the interceptor.

        Args:
            release: Restore the kernel's default authorization. Pass False
                on an error exit to keep new devices unbound until restart.
        """
        self.monitor.stop()
        if release:
            self._guard.release()


def get_platform_interceptor(
    block_during_analysis: bool = True,
    analysis_timeout: float = 10.0,
    state_file: Path | None = None,
) -> USBInterceptor:
    """
    Get the appropriate interceptor for the current platform.

    Returns:
        USBInterceptor instance

    Raises:
        RuntimeError: If platform is not supported
    """
    import platform

    system = platform.system().lower()
    if system == "linux":
        return USBInterceptor(
            block_during_analysis=block_during_analysis,
            analysis_timeout=analysis_timeout,
            state_file=state_file,
        )
    elif system == "windows":
        raise NotImplementedError("Windows interceptor not yet implemented")
    elif system == "darwin":
        raise NotImplementedError("macOS interceptor not yet implemented")
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
