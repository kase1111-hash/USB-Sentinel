"""
Linux USB Event Interceptor.

Captures USB device events using pyudev and libusb/PyUSB.
Provides real-time monitoring and device blocking capabilities.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Callable

import usb.core
import usb.util

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
                        "Failed to read device %04x:%04x: %s",
                        dev.idVendor, dev.idProduct, e
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
            try:
                devices.append(extract_device_info(dev))
            except usb.core.USBError:
                pass
        return devices


class USBMonitor:
    """
    USB device event monitor using pyudev.

    Provides real-time monitoring of USB device events.
    """

    def __init__(self) -> None:
        self._context = None
        self._monitor = None
        self._running = False
        self._enumerator = USBEnumerator()

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

    def _parse_udev_event(self, device) -> USBEvent | None:
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

            # Get VID/PID from udev properties
            vid = device.get("ID_VENDOR_ID")
            pid = device.get("ID_MODEL_ID")

            event = USBEvent(
                event_type=event_type,
                bus=bus,
                address=address,
                device_path=device.device_node or "",
                sys_path=device.sys_path,
                vid=vid,
                pid=pid,
            )

            # Try to get full descriptor for add events
            if event_type == EventType.ADD:
                try:
                    event.descriptor = self._enumerator.find_device(bus, address)
                except Exception as e:
                    logger.debug("Could not get descriptor: %s", e)

            return event

        except Exception as e:
            logger.error("Error parsing udev event: %s", e)
            return None

    async def monitor_events(self) -> AsyncIterator[USBEvent]:
        """
        Asynchronously monitor USB events.

        Yields:
            USBEvent for each device add/remove event.
        """
        import pyudev

        self._ensure_monitor()
        self._running = True

        logger.info("Starting USB event monitor")

        # Start monitoring
        self._monitor.start()

        try:
            while self._running:
                # Check for events with a timeout
                device = self._monitor.poll(timeout=0.5)
                if device is not None:
                    event = self._parse_udev_event(device)
                    if event is not None:
                        logger.debug(
                            "USB event: %s %s (VID=%s PID=%s)",
                            event.event_type.value,
                            event.device_id,
                            event.vid,
                            event.pid,
                        )
                        yield event
                else:
                    # Yield control to event loop
                    await asyncio.sleep(0)
        finally:
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
            logger.warning(
                "Not running as root. Device authorization control may not work."
            )

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
                except (ValueError, IOError):
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
        except IOError:
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
                "Device %d:%d %s",
                bus, address,
                "authorized" if authorized else "deauthorized"
            )
            return True
        except IOError as e:
            logger.error(
                "Failed to %s device %d:%d: %s",
                "authorize" if authorized else "deauthorize",
                bus, address, e
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
        except IOError:
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
        except IOError:
            return False


class USBInterceptor:
    """
    High-level USB interception interface.

    Combines enumeration, monitoring, and authorization control.
    """

    def __init__(
        self,
        block_during_analysis: bool = True,
        analysis_timeout: float = 10.0,
    ) -> None:
        """
        Initialize the interceptor.

        Args:
            block_during_analysis: Whether to block devices during analysis
            analysis_timeout: Timeout for analysis in seconds
        """
        self.enumerator = USBEnumerator()
        self.monitor = USBMonitor()
        self.authorizer = DeviceAuthorizer()
        self.block_during_analysis = block_during_analysis
        self.analysis_timeout = analysis_timeout
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

    async def events(self) -> AsyncIterator[USBEvent]:
        """
        Async iterator for USB events.

        If block_during_analysis is True, devices are blocked
        until the event is processed.
        """
        async for event in self.monitor.monitor_events():
            # Block device if configured
            if (
                self.block_during_analysis
                and event.event_type == EventType.ADD
            ):
                self.authorizer.deauthorize(event.bus, event.address)
                logger.debug("Blocked device %s pending analysis", event.device_id)

            yield event

            # Notify handlers
            for handler in self._event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error("Event handler error: %s", e)

    def allow_device(self, event: USBEvent) -> bool:
        """
        Allow a device after analysis.

        Args:
            event: The USB event for the device

        Returns:
            True if device was authorized successfully.
        """
        return self.authorizer.authorize(event.bus, event.address)

    def block_device(self, event: USBEvent) -> bool:
        """
        Block a device (keep it deauthorized).

        Args:
            event: The USB event for the device

        Returns:
            True if device was deauthorized successfully.
        """
        return self.authorizer.deauthorize(event.bus, event.address)

    def stop(self) -> None:
        """Stop the interceptor."""
        self.monitor.stop()


def get_platform_interceptor() -> USBInterceptor:
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
        return USBInterceptor()
    elif system == "windows":
        raise NotImplementedError("Windows interceptor not yet implemented")
    elif system == "darwin":
        raise NotImplementedError("macOS interceptor not yet implemented")
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
