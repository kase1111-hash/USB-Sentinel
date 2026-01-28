"""
USB Descriptor parsing and data structures.

Extracts and parses USB device descriptors for policy evaluation.
Provides comprehensive serialization and analysis helpers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EndpointDescriptor:
    """USB Endpoint Descriptor."""

    address: int
    attributes: int
    max_packet_size: int
    interval: int

    @property
    def direction(self) -> str:
        """Get endpoint direction (IN or OUT)."""
        return "IN" if self.address & 0x80 else "OUT"

    @property
    def endpoint_number(self) -> int:
        """Get endpoint number (0-15)."""
        return self.address & 0x0F

    @property
    def transfer_type(self) -> str:
        """Get transfer type."""
        types = ["Control", "Isochronous", "Bulk", "Interrupt"]
        return types[self.attributes & 0x03]

    @property
    def transfer_type_code(self) -> int:
        """Get transfer type code."""
        return self.attributes & 0x03

    @property
    def is_bulk(self) -> bool:
        """Check if bulk transfer endpoint."""
        return self.transfer_type_code == 0x02

    @property
    def is_interrupt(self) -> bool:
        """Check if interrupt transfer endpoint."""
        return self.transfer_type_code == 0x03

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "address": f"0x{self.address:02X}",
            "address_raw": self.address,
            "attributes": f"0x{self.attributes:02X}",
            "attributes_raw": self.attributes,
            "max_packet_size": self.max_packet_size,
            "interval": self.interval,
            "direction": self.direction,
            "endpoint_number": self.endpoint_number,
            "transfer_type": self.transfer_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EndpointDescriptor:
        """Create from dictionary."""
        return cls(
            address=data.get("address_raw", data.get("address", 0)),
            attributes=data.get("attributes_raw", data.get("attributes", 0)),
            max_packet_size=data.get("max_packet_size", 0),
            interval=data.get("interval", 0),
        )


@dataclass
class InterfaceDescriptor:
    """USB Interface Descriptor."""

    interface_class: int
    interface_subclass: int
    interface_protocol: int
    num_endpoints: int
    endpoints: list[EndpointDescriptor] = field(default_factory=list)
    interface_number: int = 0
    alternate_setting: int = 0
    interface_string: str | None = None

    @property
    def class_name(self) -> str:
        """Get human-readable class name."""
        class_names = {
            0x00: "Defined at Interface",
            0x01: "Audio",
            0x02: "Communications",
            0x03: "HID",
            0x05: "Physical",
            0x06: "Image",
            0x07: "Printer",
            0x08: "Mass Storage",
            0x09: "Hub",
            0x0A: "CDC-Data",
            0x0B: "Smart Card",
            0x0D: "Content Security",
            0x0E: "Video",
            0x0F: "Personal Healthcare",
            0x10: "Audio/Video",
            0xDC: "Diagnostic",
            0xE0: "Wireless",
            0xEF: "Miscellaneous",
            0xFE: "Application Specific",
            0xFF: "Vendor Specific",
        }
        return class_names.get(
            self.interface_class, f"Unknown (0x{self.interface_class:02X})"
        )

    @property
    def is_hid(self) -> bool:
        """Check if HID interface."""
        return self.interface_class == 0x03

    @property
    def is_mass_storage(self) -> bool:
        """Check if mass storage interface."""
        return self.interface_class == 0x08

    @property
    def is_keyboard(self) -> bool:
        """Check if keyboard interface (HID boot keyboard)."""
        return (
            self.interface_class == 0x03
            and self.interface_subclass == 0x01
            and self.interface_protocol == 0x01
        )

    @property
    def is_mouse(self) -> bool:
        """Check if mouse interface (HID boot mouse)."""
        return (
            self.interface_class == 0x03
            and self.interface_subclass == 0x01
            and self.interface_protocol == 0x02
        )

    @property
    def has_bulk_endpoints(self) -> bool:
        """Check if interface has bulk transfer endpoints."""
        return any(ep.is_bulk for ep in self.endpoints)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "interface_number": self.interface_number,
            "alternate_setting": self.alternate_setting,
            "interface_class": self.interface_class,
            "interface_class_hex": f"0x{self.interface_class:02X}",
            "interface_subclass": self.interface_subclass,
            "interface_protocol": self.interface_protocol,
            "num_endpoints": self.num_endpoints,
            "class_name": self.class_name,
            "interface_string": self.interface_string,
            "is_hid": self.is_hid,
            "is_mass_storage": self.is_mass_storage,
            "is_keyboard": self.is_keyboard,
            "is_mouse": self.is_mouse,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InterfaceDescriptor:
        """Create from dictionary."""
        endpoints = [
            EndpointDescriptor.from_dict(ep)
            for ep in data.get("endpoints", [])
        ]
        return cls(
            interface_class=data.get("interface_class", 0),
            interface_subclass=data.get("interface_subclass", 0),
            interface_protocol=data.get("interface_protocol", 0),
            num_endpoints=data.get("num_endpoints", len(endpoints)),
            endpoints=endpoints,
            interface_number=data.get("interface_number", 0),
            alternate_setting=data.get("alternate_setting", 0),
            interface_string=data.get("interface_string"),
        )


@dataclass
class DeviceDescriptor:
    """USB Device Descriptor with all relevant fields."""

    vid: str  # Vendor ID (hex string)
    pid: str  # Product ID (hex string)
    device_class: int
    device_subclass: int
    device_protocol: int
    manufacturer: str | None
    product: str | None
    serial: str | None
    interfaces: list[InterfaceDescriptor] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    bus: int | None = None
    address: int | None = None
    speed: str | None = None  # "low", "full", "high", "super"
    bcd_usb: int | None = None  # USB spec version
    bcd_device: int | None = None  # Device version

    @property
    def vid_pid(self) -> str:
        """Get VID:PID string."""
        return f"{self.vid}:{self.pid}"

    @property
    def class_name(self) -> str:
        """Get human-readable device class name."""
        if self.device_class == 0:
            return "Defined at Interface"
        return InterfaceDescriptor(self.device_class, 0, 0, 0).class_name

    @property
    def display_name(self) -> str:
        """Get a display name for the device."""
        if self.product:
            return self.product
        if self.manufacturer:
            return f"{self.manufacturer} Device"
        return f"USB Device {self.vid}:{self.pid}"

    @property
    def interface_classes(self) -> set[int]:
        """Get set of all interface classes."""
        return {intf.interface_class for intf in self.interfaces}

    @property
    def total_endpoints(self) -> int:
        """Get total number of endpoints."""
        return sum(intf.num_endpoints for intf in self.interfaces)

    def has_class(self, class_code: int) -> bool:
        """Check if device or any interface has the given class."""
        if self.device_class == class_code:
            return True
        return any(intf.interface_class == class_code for intf in self.interfaces)

    @property
    def is_composite(self) -> bool:
        """Check if composite device (multiple interfaces)."""
        return len(self.interfaces) > 1

    @property
    def has_hid(self) -> bool:
        """Check if device has HID interface."""
        return self.has_class(0x03)

    @property
    def has_storage(self) -> bool:
        """Check if device has mass storage interface."""
        return self.has_class(0x08)

    @property
    def has_keyboard(self) -> bool:
        """Check if device has keyboard interface."""
        return any(intf.is_keyboard for intf in self.interfaces)

    @property
    def has_mouse(self) -> bool:
        """Check if device has mouse interface."""
        return any(intf.is_mouse for intf in self.interfaces)

    def get_interfaces_by_class(self, class_code: int) -> list[InterfaceDescriptor]:
        """Get all interfaces with a specific class."""
        return [intf for intf in self.interfaces if intf.interface_class == class_code]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "vid": self.vid,
            "pid": self.pid,
            "vid_pid": self.vid_pid,
            "device_class": self.device_class,
            "device_class_hex": f"0x{self.device_class:02X}",
            "device_subclass": self.device_subclass,
            "device_protocol": self.device_protocol,
            "class_name": self.class_name,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "display_name": self.display_name,
            "timestamp": self.timestamp.isoformat(),
            "bus": self.bus,
            "address": self.address,
            "speed": self.speed,
            "bcd_usb": self.bcd_usb,
            "bcd_device": self.bcd_device,
            "is_composite": self.is_composite,
            "has_hid": self.has_hid,
            "has_storage": self.has_storage,
            "has_keyboard": self.has_keyboard,
            "has_mouse": self.has_mouse,
            "interface_count": len(self.interfaces),
            "total_endpoints": self.total_endpoints,
            "interfaces": [intf.to_dict() for intf in self.interfaces],
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceDescriptor:
        """Create from dictionary."""
        interfaces = [
            InterfaceDescriptor.from_dict(intf)
            for intf in data.get("interfaces", [])
        ]

        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)

        return cls(
            vid=data.get("vid", "0000"),
            pid=data.get("pid", "0000"),
            device_class=data.get("device_class", 0),
            device_subclass=data.get("device_subclass", 0),
            device_protocol=data.get("device_protocol", 0),
            manufacturer=data.get("manufacturer"),
            product=data.get("product"),
            serial=data.get("serial"),
            interfaces=interfaces,
            timestamp=timestamp,
            bus=data.get("bus"),
            address=data.get("address"),
            speed=data.get("speed"),
            bcd_usb=data.get("bcd_usb"),
            bcd_device=data.get("bcd_device"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> DeviceDescriptor:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def to_summary(self) -> str:
        """Get a short summary string."""
        parts = [f"{self.vid}:{self.pid}"]
        if self.manufacturer:
            parts.append(self.manufacturer)
        if self.product:
            parts.append(self.product)
        return " - ".join(parts)


def extract_device_info(dev: Any) -> DeviceDescriptor:
    """
    Extract device information from a PyUSB device object.

    Args:
        dev: usb.core.Device object

    Returns:
        DeviceDescriptor with parsed information
    """
    # Import here to avoid hard dependency
    import usb.util

    interfaces = []
    for cfg in dev:
        for intf in cfg:
            endpoints = []
            for ep in intf:
                endpoints.append(
                    EndpointDescriptor(
                        address=ep.bEndpointAddress,
                        attributes=ep.bmAttributes,
                        max_packet_size=ep.wMaxPacketSize,
                        interval=ep.bInterval,
                    )
                )
            interfaces.append(
                InterfaceDescriptor(
                    interface_class=intf.bInterfaceClass,
                    interface_subclass=intf.bInterfaceSubClass,
                    interface_protocol=intf.bInterfaceProtocol,
                    num_endpoints=intf.bNumEndpoints,
                    endpoints=endpoints,
                    interface_number=intf.bInterfaceNumber,
                    alternate_setting=intf.bAlternateSetting,
                )
            )

    # Determine speed
    speed_map = {
        1: "low",
        2: "full",
        3: "high",
        4: "super",
        5: "super_plus",
    }
    speed = speed_map.get(getattr(dev, "speed", None))

    return DeviceDescriptor(
        vid=f"{dev.idVendor:04x}",
        pid=f"{dev.idProduct:04x}",
        device_class=dev.bDeviceClass,
        device_subclass=dev.bDeviceSubClass,
        device_protocol=dev.bDeviceProtocol,
        manufacturer=(
            usb.util.get_string(dev, dev.iManufacturer)
            if dev.iManufacturer
            else None
        ),
        product=(
            usb.util.get_string(dev, dev.iProduct) if dev.iProduct else None
        ),
        serial=(
            usb.util.get_string(dev, dev.iSerialNumber)
            if dev.iSerialNumber
            else None
        ),
        interfaces=interfaces,
        bus=dev.bus,
        address=dev.address,
        speed=speed,
        bcd_usb=dev.bcdUSB,
        bcd_device=dev.bcdDevice,
    )


def create_test_descriptor(
    vid: str = "046d",
    pid: str = "c534",
    manufacturer: str | None = "Test Manufacturer",
    product: str | None = "Test Device",
    interfaces: list[tuple[int, int, int]] | None = None,
) -> DeviceDescriptor:
    """
    Create a test descriptor for unit testing.

    Args:
        vid: Vendor ID
        pid: Product ID
        manufacturer: Manufacturer string
        product: Product string
        interfaces: List of (class, subclass, protocol) tuples

    Returns:
        DeviceDescriptor for testing
    """
    if interfaces is None:
        interfaces = [(0x03, 0x01, 0x01)]  # Default: HID keyboard

    interface_descs = [
        InterfaceDescriptor(
            interface_class=cls,
            interface_subclass=sub,
            interface_protocol=proto,
            num_endpoints=1,
            endpoints=[
                EndpointDescriptor(
                    address=0x81,
                    attributes=0x03,
                    max_packet_size=8,
                    interval=10,
                )
            ],
        )
        for cls, sub, proto in interfaces
    ]

    return DeviceDescriptor(
        vid=vid,
        pid=pid,
        device_class=0,
        device_subclass=0,
        device_protocol=0,
        manufacturer=manufacturer,
        product=product,
        serial=None,
        interfaces=interface_descs,
    )
