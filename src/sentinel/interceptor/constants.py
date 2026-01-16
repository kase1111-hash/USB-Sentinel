"""
USB Constants and Reference Data.

Comprehensive USB class codes, known vendor IDs, and security-relevant
reference data for device analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import NamedTuple


class USBClass(IntEnum):
    """USB Device/Interface Class Codes."""

    # Standard classes
    PER_INTERFACE = 0x00  # Class defined at interface level
    AUDIO = 0x01
    CDC_CONTROL = 0x02  # Communications Device Class
    HID = 0x03  # Human Interface Device
    PHYSICAL = 0x05
    IMAGE = 0x06  # Still Image Capture
    PRINTER = 0x07
    MASS_STORAGE = 0x08
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    CONTENT_SECURITY = 0x0D
    VIDEO = 0x0E
    PERSONAL_HEALTHCARE = 0x0F
    AUDIO_VIDEO = 0x10
    BILLBOARD = 0x11
    USB_TYPE_C_BRIDGE = 0x12
    DIAGNOSTIC = 0xDC
    WIRELESS_CONTROLLER = 0xE0
    MISCELLANEOUS = 0xEF
    APPLICATION_SPECIFIC = 0xFE
    VENDOR_SPECIFIC = 0xFF


class HIDSubclass(IntEnum):
    """HID Subclass Codes."""

    NONE = 0x00
    BOOT_INTERFACE = 0x01


class HIDProtocol(IntEnum):
    """HID Protocol Codes."""

    NONE = 0x00
    KEYBOARD = 0x01
    MOUSE = 0x02


class MassStorageSubclass(IntEnum):
    """Mass Storage Subclass Codes."""

    RBC = 0x01  # Reduced Block Commands
    ATAPI = 0x02  # CD/DVD
    QIC_157 = 0x03  # Tape
    UFI = 0x04  # Floppy
    SFF_8070I = 0x05
    SCSI = 0x06  # SCSI transparent


class MassStorageProtocol(IntEnum):
    """Mass Storage Protocol Codes."""

    CBI_INT = 0x00  # Control/Bulk/Interrupt with command completion
    CBI_NO_INT = 0x01  # Control/Bulk/Interrupt without completion
    BBB = 0x50  # Bulk-Only (most common)
    UAS = 0x62  # USB Attached SCSI


class TransferType(IntEnum):
    """USB Transfer Types."""

    CONTROL = 0x00
    ISOCHRONOUS = 0x01
    BULK = 0x02
    INTERRUPT = 0x03


class EndpointDirection(IntEnum):
    """USB Endpoint Direction."""

    OUT = 0x00  # Host to device
    IN = 0x80  # Device to host


class SecurityRisk(IntEnum):
    """Security risk level for USB classes."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ClassInfo(NamedTuple):
    """Information about a USB class."""

    code: int
    name: str
    risk: SecurityRisk
    description: str


# Comprehensive class information
USB_CLASS_INFO: dict[int, ClassInfo] = {
    USBClass.PER_INTERFACE: ClassInfo(
        0x00, "Per-Interface", SecurityRisk.MEDIUM,
        "Class defined at interface level; inspect interfaces"
    ),
    USBClass.AUDIO: ClassInfo(
        0x01, "Audio", SecurityRisk.LOW,
        "Audio devices (speakers, microphones)"
    ),
    USBClass.CDC_CONTROL: ClassInfo(
        0x02, "Communications", SecurityRisk.MEDIUM,
        "Modems, network adapters, serial ports"
    ),
    USBClass.HID: ClassInfo(
        0x03, "HID", SecurityRisk.CRITICAL,
        "Keyboards, mice - HIGH RISK for injection attacks"
    ),
    USBClass.PHYSICAL: ClassInfo(
        0x05, "Physical", SecurityRisk.LOW,
        "Force feedback devices"
    ),
    USBClass.IMAGE: ClassInfo(
        0x06, "Image", SecurityRisk.MEDIUM,
        "Cameras, scanners - data exfiltration risk"
    ),
    USBClass.PRINTER: ClassInfo(
        0x07, "Printer", SecurityRisk.MEDIUM,
        "Printers - data exfiltration risk"
    ),
    USBClass.MASS_STORAGE: ClassInfo(
        0x08, "Mass Storage", SecurityRisk.CRITICAL,
        "USB drives - HIGH RISK for malware delivery"
    ),
    USBClass.HUB: ClassInfo(
        0x09, "Hub", SecurityRisk.LOW,
        "USB hubs - inspect child devices"
    ),
    USBClass.CDC_DATA: ClassInfo(
        0x0A, "CDC-Data", SecurityRisk.MEDIUM,
        "Data interface for CDC devices"
    ),
    USBClass.SMART_CARD: ClassInfo(
        0x0B, "Smart Card", SecurityRisk.HIGH,
        "Smart card readers - credential access"
    ),
    USBClass.VIDEO: ClassInfo(
        0x0E, "Video", SecurityRisk.MEDIUM,
        "Webcams - privacy risk"
    ),
    USBClass.WIRELESS_CONTROLLER: ClassInfo(
        0xE0, "Wireless", SecurityRisk.HIGH,
        "Bluetooth/WiFi adapters - network attack risk"
    ),
    USBClass.MISCELLANEOUS: ClassInfo(
        0xEF, "Miscellaneous", SecurityRisk.MEDIUM,
        "Composite devices - inspect all interfaces"
    ),
    USBClass.APPLICATION_SPECIFIC: ClassInfo(
        0xFE, "Application Specific", SecurityRisk.HIGH,
        "DFU, IRDA - firmware update risk"
    ),
    USBClass.VENDOR_SPECIFIC: ClassInfo(
        0xFF, "Vendor Specific", SecurityRisk.HIGH,
        "Unknown functionality - requires analysis"
    ),
}


@dataclass
class VendorInfo:
    """Information about a USB vendor."""

    vid: str  # Hex string
    name: str
    trusted: bool = True
    notes: str = ""


# Well-known trusted vendors
TRUSTED_VENDORS: dict[str, VendorInfo] = {
    "046d": VendorInfo("046d", "Logitech", True),
    "045e": VendorInfo("045e", "Microsoft", True),
    "05ac": VendorInfo("05ac", "Apple", True),
    "8087": VendorInfo("8087", "Intel", True),
    "1d6b": VendorInfo("1d6b", "Linux Foundation", True),
    "0bda": VendorInfo("0bda", "Realtek", True),
    "8086": VendorInfo("8086", "Intel", True),
    "0781": VendorInfo("0781", "SanDisk", True),
    "0951": VendorInfo("0951", "Kingston", True),
    "1058": VendorInfo("1058", "Western Digital", True),
    "0930": VendorInfo("0930", "Toshiba", True),
    "04e8": VendorInfo("04e8", "Samsung", True),
    "0b05": VendorInfo("0b05", "ASUS", True),
    "1532": VendorInfo("1532", "Razer", True),
    "1038": VendorInfo("1038", "SteelSeries", True),
    "046a": VendorInfo("046a", "Cherry", True),
    "04f2": VendorInfo("04f2", "Chicony", True),
    "0a5c": VendorInfo("0a5c", "Broadcom", True),
    "10c4": VendorInfo("10c4", "Silicon Labs", True),
}


# Vendors commonly associated with attack hardware
SUSPICIOUS_VENDORS: dict[str, VendorInfo] = {
    "1a86": VendorInfo("1a86", "QinHeng Electronics", False,
                       "CH340 - common in DIY attack hardware"),
    "0483": VendorInfo("0483", "STMicroelectronics", False,
                       "STM32 - used in Rubber Ducky, BadUSB"),
    "03eb": VendorInfo("03eb", "Atmel", False,
                       "AVR/SAM - used in Rubber Ducky, Teensy"),
    "16c0": VendorInfo("16c0", "Van Ooijen Technische Informatica", False,
                       "Teensy, PJRC devices"),
    "1781": VendorInfo("1781", "Multiple", False,
                       "Digispark, various DIY devices"),
    "1d50": VendorInfo("1d50", "OpenMoko", False,
                       "Open source hardware, various tools"),
    "2341": VendorInfo("2341", "Arduino", False,
                       "Arduino - can be used for HID attacks"),
    "1b4f": VendorInfo("1b4f", "SparkFun", False,
                       "SparkFun Pro Micro - HID capable"),
    "239a": VendorInfo("239a", "Adafruit", False,
                       "Adafruit boards - HID capable"),
    "0525": VendorInfo("0525", "Netchip/PLX", False,
                       "USB gadget mode - various attack tools"),
}


def get_class_info(class_code: int) -> ClassInfo | None:
    """
    Get information about a USB class.

    Args:
        class_code: USB class code

    Returns:
        ClassInfo or None if unknown
    """
    return USB_CLASS_INFO.get(class_code)


def get_class_name(class_code: int) -> str:
    """
    Get human-readable name for a USB class.

    Args:
        class_code: USB class code

    Returns:
        Class name string
    """
    info = USB_CLASS_INFO.get(class_code)
    if info:
        return info.name
    return f"Unknown (0x{class_code:02X})"


def get_class_risk(class_code: int) -> SecurityRisk:
    """
    Get security risk level for a USB class.

    Args:
        class_code: USB class code

    Returns:
        SecurityRisk level
    """
    info = USB_CLASS_INFO.get(class_code)
    if info:
        return info.risk
    return SecurityRisk.HIGH  # Unknown classes are high risk


def is_high_risk_class(class_code: int) -> bool:
    """
    Check if a class is considered high risk.

    Args:
        class_code: USB class code

    Returns:
        True if high risk
    """
    risk = get_class_risk(class_code)
    return risk in (SecurityRisk.HIGH, SecurityRisk.CRITICAL)


def get_vendor_info(vid: str) -> VendorInfo | None:
    """
    Get information about a vendor.

    Args:
        vid: Vendor ID (hex string)

    Returns:
        VendorInfo or None if unknown
    """
    vid = vid.lower()
    if vid in TRUSTED_VENDORS:
        return TRUSTED_VENDORS[vid]
    if vid in SUSPICIOUS_VENDORS:
        return SUSPICIOUS_VENDORS[vid]
    return None


def is_trusted_vendor(vid: str) -> bool:
    """
    Check if a vendor is in the trusted list.

    Args:
        vid: Vendor ID (hex string)

    Returns:
        True if vendor is trusted
    """
    return vid.lower() in TRUSTED_VENDORS


def is_suspicious_vendor(vid: str) -> bool:
    """
    Check if a vendor is in the suspicious list.

    Args:
        vid: Vendor ID (hex string)

    Returns:
        True if vendor is suspicious
    """
    return vid.lower() in SUSPICIOUS_VENDORS


def get_transfer_type_name(transfer_type: int) -> str:
    """
    Get name for a transfer type.

    Args:
        transfer_type: Transfer type code (from endpoint attributes & 0x03)

    Returns:
        Transfer type name
    """
    names = {
        TransferType.CONTROL: "Control",
        TransferType.ISOCHRONOUS: "Isochronous",
        TransferType.BULK: "Bulk",
        TransferType.INTERRUPT: "Interrupt",
    }
    return names.get(transfer_type, f"Unknown (0x{transfer_type:02X})")


def get_endpoint_direction(address: int) -> str:
    """
    Get endpoint direction from address.

    Args:
        address: Endpoint address

    Returns:
        "IN" or "OUT"
    """
    return "IN" if address & 0x80 else "OUT"
