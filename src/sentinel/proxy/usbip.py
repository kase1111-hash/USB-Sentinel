"""
USB/IP wrapper for device proxying.

Provides controlled device attachment through USB/IP, allowing
traffic inspection and behavioral analysis before full device access.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class ProxyStatus(Enum):
    """Status of a proxied device."""

    UNBOUND = "unbound"
    BOUND = "bound"
    EXPORTED = "exported"
    ATTACHED = "attached"
    ERROR = "error"


@dataclass
class ProxyDevice:
    """Represents a device being proxied through USB/IP."""

    bus_id: str
    vid: str
    pid: str
    status: ProxyStatus = ProxyStatus.UNBOUND
    local_port: int | None = None
    remote_host: str | None = None
    attached_at: datetime | None = None
    error_message: str | None = None

    @property
    def device_id(self) -> str:
        """Get VID:PID string."""
        return f"{self.vid}:{self.pid}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "bus_id": self.bus_id,
            "vid": self.vid,
            "pid": self.pid,
            "status": self.status.value,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "attached_at": self.attached_at.isoformat() if self.attached_at else None,
            "error_message": self.error_message,
        }


@dataclass
class USBIPConfig:
    """Configuration for USB/IP proxy."""

    usbip_path: str = "/usr/sbin/usbip"
    usbipd_path: str = "/usr/sbin/usbipd"
    bind_timeout: float = 5.0
    attach_timeout: float = 10.0
    local_host: str = "localhost"
    base_port: int = 3240
    max_devices: int = 10


class USBIPError(Exception):
    """Exception raised for USB/IP operations."""

    def __init__(self, message: str, returncode: int = -1, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class USBIPProxy:
    """
    USB/IP proxy manager for sandboxed device access.

    Provides controlled device attachment through USB/IP, enabling
    traffic inspection before granting full device access.
    """

    def __init__(self, config: USBIPConfig | None = None) -> None:
        """
        Initialize the USB/IP proxy.

        Args:
            config: USB/IP configuration
        """
        self.config = config or USBIPConfig()
        self._devices: dict[str, ProxyDevice] = {}
        self._daemon_process: subprocess.Popen | None = None
        self._next_port = self.config.base_port

        # Statistics
        self._bind_count = 0
        self._attach_count = 0
        self._error_count = 0

    def _run_command(
        self,
        args: list[str],
        timeout: float | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Run a command and return the result.

        Args:
            args: Command arguments
            timeout: Command timeout in seconds
            check: Raise exception on non-zero return code

        Returns:
            CompletedProcess result

        Raises:
            USBIPError: If command fails and check=True
        """
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout or 30.0,
            )
            if check and result.returncode != 0:
                raise USBIPError(
                    f"Command failed: {' '.join(args)}",
                    returncode=result.returncode,
                    stderr=result.stderr,
                )
            return result
        except subprocess.TimeoutExpired as e:
            raise USBIPError(f"Command timed out: {' '.join(args)}") from e
        except FileNotFoundError as e:
            raise USBIPError(f"Command not found: {args[0]}") from e

    def check_available(self) -> bool:
        """
        Check if USB/IP is available on the system.

        Returns:
            True if USB/IP tools are available
        """
        try:
            result = self._run_command(
                [self.config.usbip_path, "version"],
                check=False,
            )
            return result.returncode == 0
        except USBIPError:
            return False

    def list_local_devices(self) -> list[dict[str, str]]:
        """
        List USB devices available for binding.

        Returns:
            List of device info dictionaries
        """
        try:
            result = self._run_command(
                [self.config.usbip_path, "list", "-l"],
                check=False,
            )
            return self._parse_device_list(result.stdout)
        except USBIPError as e:
            logger.error("Failed to list devices: %s", e)
            return []

    def _parse_device_list(self, output: str) -> list[dict[str, str]]:
        """Parse usbip list output."""
        devices = []
        # Pattern: busid X-Y (VID:PID)
        pattern = r"busid\s+(\S+)\s+\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)"

        for match in re.finditer(pattern, output):
            devices.append({
                "bus_id": match.group(1),
                "vid": match.group(2).lower(),
                "pid": match.group(3).lower(),
            })
        return devices

    def bind_device(self, bus_id: str) -> ProxyDevice:
        """
        Bind a device for USB/IP export.

        Args:
            bus_id: Bus ID of device to bind (e.g., "1-2")

        Returns:
            ProxyDevice with updated status

        Raises:
            USBIPError: If binding fails
        """
        # Check if already bound
        if bus_id in self._devices:
            device = self._devices[bus_id]
            if device.status in (ProxyStatus.BOUND, ProxyStatus.EXPORTED):
                return device

        # Get device info
        local_devices = self.list_local_devices()
        device_info = next(
            (d for d in local_devices if d["bus_id"] == bus_id),
            None,
        )

        if device_info is None:
            raise USBIPError(f"Device not found: {bus_id}")

        # Create proxy device
        device = ProxyDevice(
            bus_id=bus_id,
            vid=device_info["vid"],
            pid=device_info["pid"],
        )

        try:
            # Bind the device
            self._run_command(
                [self.config.usbip_path, "bind", "-b", bus_id],
                timeout=self.config.bind_timeout,
            )
            device.status = ProxyStatus.BOUND
            self._bind_count += 1
            logger.info("Bound device %s (%s)", bus_id, device.device_id)

        except USBIPError as e:
            device.status = ProxyStatus.ERROR
            device.error_message = str(e)
            self._error_count += 1
            logger.error("Failed to bind device %s: %s", bus_id, e)
            raise

        self._devices[bus_id] = device
        return device

    def unbind_device(self, bus_id: str) -> bool:
        """
        Unbind a device from USB/IP.

        Args:
            bus_id: Bus ID of device to unbind

        Returns:
            True if unbind succeeded
        """
        try:
            self._run_command(
                [self.config.usbip_path, "unbind", "-b", bus_id],
                check=False,
            )
            if bus_id in self._devices:
                self._devices[bus_id].status = ProxyStatus.UNBOUND
            logger.info("Unbound device %s", bus_id)
            return True
        except USBIPError as e:
            logger.error("Failed to unbind device %s: %s", bus_id, e)
            return False

    def attach_device(
        self,
        host: str,
        bus_id: str,
        port: int | None = None,
    ) -> ProxyDevice:
        """
        Attach a remote device via USB/IP.

        Args:
            host: Remote host exporting the device
            bus_id: Bus ID of device to attach
            port: USB/IP port (default: 3240)

        Returns:
            ProxyDevice with updated status

        Raises:
            USBIPError: If attachment fails
        """
        port = port or self.config.base_port

        # Create or get proxy device
        if bus_id in self._devices:
            device = self._devices[bus_id]
        else:
            device = ProxyDevice(
                bus_id=bus_id,
                vid="0000",
                pid="0000",
            )

        try:
            self._run_command(
                [
                    self.config.usbip_path,
                    "attach",
                    "-r", host,
                    "-b", bus_id,
                ],
                timeout=self.config.attach_timeout,
            )
            device.status = ProxyStatus.ATTACHED
            device.remote_host = host
            device.local_port = port
            device.attached_at = datetime.utcnow()
            self._attach_count += 1
            logger.info("Attached device %s from %s", bus_id, host)

        except USBIPError as e:
            device.status = ProxyStatus.ERROR
            device.error_message = str(e)
            self._error_count += 1
            logger.error("Failed to attach device %s: %s", bus_id, e)
            raise

        self._devices[bus_id] = device
        return device

    def detach_device(self, port: int) -> bool:
        """
        Detach a device by port number.

        Args:
            port: Local port number of attached device

        Returns:
            True if detach succeeded
        """
        try:
            self._run_command(
                [self.config.usbip_path, "detach", "-p", str(port)],
                check=False,
            )
            # Update device status
            for device in self._devices.values():
                if device.local_port == port:
                    device.status = ProxyStatus.UNBOUND
                    device.local_port = None
            logger.info("Detached device on port %d", port)
            return True
        except USBIPError as e:
            logger.error("Failed to detach port %d: %s", port, e)
            return False

    def list_attached(self) -> list[dict[str, Any]]:
        """
        List currently attached devices.

        Returns:
            List of attached device info
        """
        try:
            result = self._run_command(
                [self.config.usbip_path, "port"],
                check=False,
            )
            return self._parse_port_list(result.stdout)
        except USBIPError:
            return []

    def _parse_port_list(self, output: str) -> list[dict[str, Any]]:
        """Parse usbip port output."""
        attached = []
        # Pattern: Port XX: <...> at ...
        pattern = r"Port\s+(\d+):.+\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)"

        for match in re.finditer(pattern, output):
            attached.append({
                "port": int(match.group(1)),
                "vid": match.group(2).lower(),
                "pid": match.group(3).lower(),
            })
        return attached

    def start_daemon(self) -> bool:
        """
        Start the USB/IP daemon for device export.

        Returns:
            True if daemon started successfully
        """
        if self._daemon_process is not None:
            return True

        try:
            self._daemon_process = subprocess.Popen(
                [self.config.usbipd_path, "-D"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info("Started USB/IP daemon (PID %d)", self._daemon_process.pid)
            return True
        except Exception as e:
            logger.error("Failed to start USB/IP daemon: %s", e)
            return False

    def stop_daemon(self) -> None:
        """Stop the USB/IP daemon."""
        if self._daemon_process is not None:
            self._daemon_process.terminate()
            try:
                self._daemon_process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._daemon_process.kill()
            self._daemon_process = None
            logger.info("Stopped USB/IP daemon")

    def get_device(self, bus_id: str) -> ProxyDevice | None:
        """Get a proxied device by bus ID."""
        return self._devices.get(bus_id)

    def get_all_devices(self) -> list[ProxyDevice]:
        """Get all proxied devices."""
        return list(self._devices.values())

    def get_statistics(self) -> dict[str, Any]:
        """Get proxy statistics."""
        return {
            "total_devices": len(self._devices),
            "bind_count": self._bind_count,
            "attach_count": self._attach_count,
            "error_count": self._error_count,
            "daemon_running": self._daemon_process is not None,
        }

    def cleanup(self) -> None:
        """Clean up all proxied devices and stop daemon."""
        # Unbind all devices
        for bus_id in list(self._devices.keys()):
            self.unbind_device(bus_id)

        # Detach all ports
        for device in self.list_attached():
            self.detach_device(device["port"])

        # Stop daemon
        self.stop_daemon()

        self._devices.clear()
        logger.info("USB/IP proxy cleanup complete")


class MockUSBIPProxy:
    """
    Mock USB/IP proxy for testing without actual USB/IP.

    Simulates USB/IP operations for unit testing.
    """

    def __init__(self, config: USBIPConfig | None = None) -> None:
        """Initialize mock proxy."""
        self.config = config or USBIPConfig()
        self._devices: dict[str, ProxyDevice] = {}
        self._attached_ports: dict[int, str] = {}
        self._next_port = 0
        self._available = True

        # Statistics
        self._bind_count = 0
        self._attach_count = 0

    def check_available(self) -> bool:
        """Check if mock proxy is available."""
        return self._available

    def set_available(self, available: bool) -> None:
        """Set availability for testing."""
        self._available = available

    def list_local_devices(self) -> list[dict[str, str]]:
        """List mock local devices."""
        return [
            {"bus_id": "1-1", "vid": "046d", "pid": "c52b"},
            {"bus_id": "1-2", "vid": "1234", "pid": "5678"},
            {"bus_id": "2-1", "vid": "dead", "pid": "beef"},
        ]

    def bind_device(self, bus_id: str) -> ProxyDevice:
        """Bind a mock device."""
        if not self._available:
            raise USBIPError("USB/IP not available")

        local_devices = self.list_local_devices()
        device_info = next(
            (d for d in local_devices if d["bus_id"] == bus_id),
            None,
        )

        if device_info is None:
            raise USBIPError(f"Device not found: {bus_id}")

        device = ProxyDevice(
            bus_id=bus_id,
            vid=device_info["vid"],
            pid=device_info["pid"],
            status=ProxyStatus.BOUND,
        )
        self._devices[bus_id] = device
        self._bind_count += 1
        return device

    def unbind_device(self, bus_id: str) -> bool:
        """Unbind a mock device."""
        if bus_id in self._devices:
            self._devices[bus_id].status = ProxyStatus.UNBOUND
            return True
        return False

    def attach_device(
        self,
        host: str,
        bus_id: str,
        port: int | None = None,
    ) -> ProxyDevice:
        """Attach a mock device."""
        if not self._available:
            raise USBIPError("USB/IP not available")

        port = port or self._next_port
        self._next_port += 1

        device = ProxyDevice(
            bus_id=bus_id,
            vid="0000",
            pid="0000",
            status=ProxyStatus.ATTACHED,
            local_port=port,
            remote_host=host,
            attached_at=datetime.utcnow(),
        )
        self._devices[bus_id] = device
        self._attached_ports[port] = bus_id
        self._attach_count += 1
        return device

    def detach_device(self, port: int) -> bool:
        """Detach a mock device."""
        if port in self._attached_ports:
            bus_id = self._attached_ports.pop(port)
            if bus_id in self._devices:
                self._devices[bus_id].status = ProxyStatus.UNBOUND
                self._devices[bus_id].local_port = None
            return True
        return False

    def list_attached(self) -> list[dict[str, Any]]:
        """List mock attached devices."""
        attached = []
        for port, bus_id in self._attached_ports.items():
            device = self._devices.get(bus_id)
            if device:
                attached.append({
                    "port": port,
                    "vid": device.vid,
                    "pid": device.pid,
                })
        return attached

    def start_daemon(self) -> bool:
        """Start mock daemon."""
        return True

    def stop_daemon(self) -> None:
        """Stop mock daemon."""
        pass

    def get_device(self, bus_id: str) -> ProxyDevice | None:
        """Get a mock device."""
        return self._devices.get(bus_id)

    def get_all_devices(self) -> list[ProxyDevice]:
        """Get all mock devices."""
        return list(self._devices.values())

    def get_statistics(self) -> dict[str, Any]:
        """Get mock statistics."""
        return {
            "total_devices": len(self._devices),
            "bind_count": self._bind_count,
            "attach_count": self._attach_count,
            "error_count": 0,
            "daemon_running": True,
            "mock": True,
        }

    def cleanup(self) -> None:
        """Clean up mock state."""
        self._devices.clear()
        self._attached_ports.clear()


def create_proxy(use_mock: bool = False) -> USBIPProxy | MockUSBIPProxy:
    """
    Create a USB/IP proxy instance.

    Args:
        use_mock: Use mock proxy for testing

    Returns:
        Proxy instance
    """
    if use_mock:
        return MockUSBIPProxy()
    return USBIPProxy()
