"""
USB Descriptor parsing and data structures.

Extracts and parses USB device descriptors for policy evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
    def transfer_type(self) -> str:
        """Get transfer type."""
        types = ["Control", "Isochronous", "Bulk", "Interrupt"]
        return types[self.attributes & 0x03]


@dataclass
class InterfaceDescriptor:
    """USB Interface Descriptor."""

    interface_class: int
    interface_subclass: int
    interface_protocol: int
    num_endpoints: int
    endpoints: list[EndpointDescriptor] = field(default_factory=list)

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
            0x0E: "Video",
            0xE0: "Wireless",
            0xEF: "Miscellaneous",
            0xFE: "Application Specific",
            0xFF: "Vendor Specific",
        }
        return class_names.get(self.interface_class, f"Unknown (0x{self.interface_class:02X})")


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
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def class_name(self) -> str:
        """Get human-readable device class name."""
        if self.device_class == 0:
            return "Defined at Interface"
        # Reuse interface class names
        return InterfaceDescriptor(
            self.device_class, 0, 0, 0
        ).class_name

    def has_class(self, class_code: int) -> bool:
        """Check if device or any interface has the given class."""
        if self.device_class == class_code:
            return True
        return any(intf.interface_class == class_code for intf in self.interfaces)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "vid": self.vid,
            "pid": self.pid,
            "device_class": self.device_class,
            "device_subclass": self.device_subclass,
            "device_protocol": self.device_protocol,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "timestamp": self.timestamp.isoformat(),
            "interfaces": [
                {
                    "interface_class": intf.interface_class,
                    "interface_subclass": intf.interface_subclass,
                    "interface_protocol": intf.interface_protocol,
                    "num_endpoints": intf.num_endpoints,
                    "class_name": intf.class_name,
                }
                for intf in self.interfaces
            ],
        }


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
                )
            )

    return DeviceDescriptor(
        vid=f"{dev.idVendor:04x}",
        pid=f"{dev.idProduct:04x}",
        device_class=dev.bDeviceClass,
        device_subclass=dev.bDeviceSubClass,
        device_protocol=dev.bDeviceProtocol,
        manufacturer=usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else None,
        product=usb.util.get_string(dev, dev.iProduct) if dev.iProduct else None,
        serial=usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else None,
        interfaces=interfaces,
    )
