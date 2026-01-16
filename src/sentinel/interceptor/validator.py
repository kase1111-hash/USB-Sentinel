"""
USB Descriptor Validator.

Validates USB device descriptors for consistency and detects
anomalies that may indicate malicious devices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.interceptor.descriptors import DeviceDescriptor, InterfaceDescriptor


class AnomalyType(Enum):
    """Types of descriptor anomalies."""

    # Class-related anomalies
    CLASS_MISMATCH = "class_mismatch"
    SUSPICIOUS_CLASS_COMBO = "suspicious_class_combo"
    MULTIPLE_HIGH_RISK_CLASSES = "multiple_high_risk_classes"

    # String anomalies
    MISSING_MANUFACTURER = "missing_manufacturer"
    MISSING_PRODUCT = "missing_product"
    GENERIC_STRINGS = "generic_strings"
    SUSPICIOUS_STRINGS = "suspicious_strings"

    # Endpoint anomalies
    ENDPOINT_COUNT_MISMATCH = "endpoint_count_mismatch"
    EXCESSIVE_ENDPOINTS = "excessive_endpoints"
    UNUSUAL_ENDPOINT_CONFIG = "unusual_endpoint_config"

    # Known attack patterns
    ATTACK_SIGNATURE = "attack_signature"
    RUBBER_DUCKY_PATTERN = "rubber_ducky_pattern"
    BADUSB_PATTERN = "badusb_pattern"

    # Other anomalies
    VENDOR_ID_SPOOFING = "vendor_id_spoofing"
    DESCRIPTOR_INCONSISTENCY = "descriptor_inconsistency"


class Severity(Enum):
    """Anomaly severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    """
    Detected anomaly in a device descriptor.
    """

    anomaly_type: AnomalyType
    severity: Severity
    description: str
    field: str | None = None
    expected: str | None = None
    actual: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "field": self.field,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass
class ValidationResult:
    """
    Result of descriptor validation.
    """

    is_valid: bool
    anomalies: list[Anomaly] = field(default_factory=list)
    risk_score: int = 0  # 0-100 based on anomalies

    @property
    def has_anomalies(self) -> bool:
        """Check if any anomalies were detected."""
        return len(self.anomalies) > 0

    @property
    def highest_severity(self) -> Severity | None:
        """Get highest severity among anomalies."""
        if not self.anomalies:
            return None
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for severity in severity_order:
            if any(a.severity == severity for a in self.anomalies):
                return severity
        return None

    def add_anomaly(self, anomaly: Anomaly) -> None:
        """Add an anomaly to the result."""
        self.anomalies.append(anomaly)
        self._update_risk_score()

    def _update_risk_score(self) -> None:
        """Update risk score based on anomalies."""
        score = 0
        severity_scores = {
            Severity.INFO: 5,
            Severity.LOW: 10,
            Severity.MEDIUM: 20,
            Severity.HIGH: 35,
            Severity.CRITICAL: 50,
        }
        for anomaly in self.anomalies:
            score += severity_scores.get(anomaly.severity, 0)
        self.risk_score = min(100, score)
        self.is_valid = self.risk_score < 50

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "risk_score": self.risk_score,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "anomaly_count": len(self.anomalies),
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


# USB Class codes considered high-risk
HIGH_RISK_CLASSES = {
    0x03,  # HID - keyboard/mouse injection
    0x08,  # Mass Storage - malware delivery
    0xFE,  # Application Specific - firmware update
    0xFF,  # Vendor Specific - unknown behavior
}

# Known generic/placeholder strings used by attack devices
GENERIC_STRINGS = {
    "usb device",
    "usb composite device",
    "usb input device",
    "generic usb device",
    "usb keyboard",
    "usb mouse",
    "usb storage",
}

# Suspicious string patterns (regex)
SUSPICIOUS_PATTERNS = [
    r"(?i)rubber.?ducky",
    r"(?i)bad.?usb",
    r"(?i)bash.?bunny",
    r"(?i)lan.?turtle",
    r"(?i)usb.?armory",
    r"(?i)teensy",
    r"(?i)digispark",
    r"(?i)attiny",
    r"(?i)arduino.*(leonardo|micro|pro)",
    r"(?i)p4wnp1",
]

# Known attack device VID:PID signatures
KNOWN_ATTACK_SIGNATURES = {
    ("1a86", "7523"),  # CH340 - common in attack hardware
    ("0483", "df11"),  # STM32 DFU mode
    ("03eb", "2ff4"),  # Atmel DFU (Rubber Ducky)
    ("16c0", "0483"),  # Teensy
    ("1781", "0c9f"),  # Digispark
}

# Valid class/endpoint combinations
EXPECTED_ENDPOINTS = {
    0x01: (1, 4),   # Audio: 1-4 endpoints
    0x02: (1, 4),   # CDC: 1-4 endpoints
    0x03: (1, 2),   # HID: 1-2 endpoints
    0x07: (1, 3),   # Printer: 1-3 endpoints
    0x08: (2, 4),   # Mass Storage: 2-4 endpoints
    0x09: (1, 1),   # Hub: 1 endpoint
    0x0E: (1, 4),   # Video: 1-4 endpoints
}


class DescriptorValidator:
    """
    Validates USB device descriptors for anomalies.
    """

    def __init__(self) -> None:
        self._suspicious_patterns = [
            re.compile(p) for p in SUSPICIOUS_PATTERNS
        ]

    def validate(self, descriptor: DeviceDescriptor) -> ValidationResult:
        """
        Validate a device descriptor.

        Args:
            descriptor: Device descriptor to validate

        Returns:
            ValidationResult with any detected anomalies
        """
        result = ValidationResult(is_valid=True)

        # Run all validation checks
        self._check_known_signatures(descriptor, result)
        self._check_class_consistency(descriptor, result)
        self._check_string_anomalies(descriptor, result)
        self._check_endpoint_consistency(descriptor, result)
        self._check_attack_patterns(descriptor, result)
        self._check_suspicious_combinations(descriptor, result)

        return result

    def _check_known_signatures(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for known attack device signatures."""
        vid_pid = (descriptor.vid.lower(), descriptor.pid.lower())

        if vid_pid in KNOWN_ATTACK_SIGNATURES:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.ATTACK_SIGNATURE,
                severity=Severity.CRITICAL,
                description="Device matches known attack hardware signature",
                field="vid:pid",
                actual=f"{descriptor.vid}:{descriptor.pid}",
            ))

    def _check_class_consistency(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for class-related anomalies."""
        interface_classes = {intf.interface_class for intf in descriptor.interfaces}

        # Check for multiple high-risk classes
        high_risk_present = interface_classes & HIGH_RISK_CLASSES
        if len(high_risk_present) > 1:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.MULTIPLE_HIGH_RISK_CLASSES,
                severity=Severity.HIGH,
                description="Device has multiple high-risk interface classes",
                field="interface_classes",
                actual=str(list(high_risk_present)),
            ))

        # HID + Storage is highly suspicious
        if 0x03 in interface_classes and 0x08 in interface_classes:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.SUSPICIOUS_CLASS_COMBO,
                severity=Severity.CRITICAL,
                description="HID device with mass storage capability - likely attack device",
                field="interface_classes",
                actual="HID (0x03) + Mass Storage (0x08)",
            ))

        # Check device class vs interface class consistency
        if descriptor.device_class != 0:
            # Device class should match interface classes
            if descriptor.device_class not in interface_classes:
                result.add_anomaly(Anomaly(
                    anomaly_type=AnomalyType.CLASS_MISMATCH,
                    severity=Severity.MEDIUM,
                    description="Device class doesn't match interface classes",
                    field="device_class",
                    expected=f"One of {list(interface_classes)}",
                    actual=str(descriptor.device_class),
                ))

    def _check_string_anomalies(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for string-related anomalies."""
        # Missing manufacturer
        if not descriptor.manufacturer:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.MISSING_MANUFACTURER,
                severity=Severity.MEDIUM,
                description="Device has no manufacturer string",
                field="manufacturer",
            ))

        # Missing product
        if not descriptor.product:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.MISSING_PRODUCT,
                severity=Severity.LOW,
                description="Device has no product string",
                field="product",
            ))

        # Generic strings
        for field_name, value in [
            ("manufacturer", descriptor.manufacturer),
            ("product", descriptor.product),
        ]:
            if value and value.lower().strip() in GENERIC_STRINGS:
                result.add_anomaly(Anomaly(
                    anomaly_type=AnomalyType.GENERIC_STRINGS,
                    severity=Severity.MEDIUM,
                    description=f"Device has generic {field_name} string",
                    field=field_name,
                    actual=value,
                ))

        # Suspicious patterns
        for field_name, value in [
            ("manufacturer", descriptor.manufacturer),
            ("product", descriptor.product),
        ]:
            if value:
                for pattern in self._suspicious_patterns:
                    if pattern.search(value):
                        result.add_anomaly(Anomaly(
                            anomaly_type=AnomalyType.SUSPICIOUS_STRINGS,
                            severity=Severity.HIGH,
                            description=f"Device {field_name} matches attack device pattern",
                            field=field_name,
                            actual=value,
                        ))
                        break

    def _check_endpoint_consistency(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for endpoint-related anomalies."""
        for intf in descriptor.interfaces:
            # Check declared vs actual endpoint count
            if intf.num_endpoints != len(intf.endpoints):
                result.add_anomaly(Anomaly(
                    anomaly_type=AnomalyType.ENDPOINT_COUNT_MISMATCH,
                    severity=Severity.LOW,
                    description="Declared endpoint count doesn't match actual",
                    field="num_endpoints",
                    expected=str(intf.num_endpoints),
                    actual=str(len(intf.endpoints)),
                ))

            # Check expected endpoints for class
            if intf.interface_class in EXPECTED_ENDPOINTS:
                min_ep, max_ep = EXPECTED_ENDPOINTS[intf.interface_class]
                if not (min_ep <= intf.num_endpoints <= max_ep):
                    result.add_anomaly(Anomaly(
                        anomaly_type=AnomalyType.UNUSUAL_ENDPOINT_CONFIG,
                        severity=Severity.MEDIUM,
                        description=f"Unusual endpoint count for class 0x{intf.interface_class:02X}",
                        field="num_endpoints",
                        expected=f"{min_ep}-{max_ep}",
                        actual=str(intf.num_endpoints),
                    ))

        # Check for excessive total endpoints
        total_endpoints = sum(intf.num_endpoints for intf in descriptor.interfaces)
        if total_endpoints > 10:
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.EXCESSIVE_ENDPOINTS,
                severity=Severity.MEDIUM,
                description="Device has unusually many endpoints",
                field="total_endpoints",
                actual=str(total_endpoints),
            ))

    def _check_attack_patterns(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for known attack device patterns."""
        # Rubber Ducky pattern: HID with ATMEL vendor string
        if any(intf.interface_class == 0x03 for intf in descriptor.interfaces):
            if descriptor.manufacturer and "atmel" in descriptor.manufacturer.lower():
                result.add_anomaly(Anomaly(
                    anomaly_type=AnomalyType.RUBBER_DUCKY_PATTERN,
                    severity=Severity.CRITICAL,
                    description="Device matches Rubber Ducky pattern (HID + ATMEL)",
                    field="manufacturer",
                    actual=descriptor.manufacturer,
                ))

        # BadUSB pattern: Multiple re-enumeration or class changes
        # (This would require tracking state across connections)

    def _check_suspicious_combinations(
        self,
        descriptor: DeviceDescriptor,
        result: ValidationResult,
    ) -> None:
        """Check for suspicious attribute combinations."""
        interface_classes = {intf.interface_class for intf in descriptor.interfaces}

        # HID device with bulk endpoints (unusual, may indicate data exfil)
        if 0x03 in interface_classes:
            for intf in descriptor.interfaces:
                if intf.interface_class == 0x03:
                    for ep in intf.endpoints:
                        if (ep.attributes & 0x03) == 0x02:  # Bulk transfer
                            result.add_anomaly(Anomaly(
                                anomaly_type=AnomalyType.UNUSUAL_ENDPOINT_CONFIG,
                                severity=Severity.HIGH,
                                description="HID device with bulk transfer endpoint",
                                field="endpoint_type",
                                expected="Interrupt (0x03)",
                                actual="Bulk (0x02)",
                            ))

        # CDC device claiming to be keyboard
        if 0x02 in interface_classes and 0x03 in interface_classes:
            # Check if HID is keyboard subclass
            for intf in descriptor.interfaces:
                if intf.interface_class == 0x03 and intf.interface_protocol == 1:
                    result.add_anomaly(Anomaly(
                        anomaly_type=AnomalyType.SUSPICIOUS_CLASS_COMBO,
                        severity=Severity.HIGH,
                        description="CDC device with keyboard interface - possible attack device",
                        field="interface_classes",
                        actual="CDC + HID Keyboard",
                    ))


def validate_descriptor(descriptor: DeviceDescriptor) -> ValidationResult:
    """
    Validate a device descriptor.

    Convenience function for quick validation.

    Args:
        descriptor: Device descriptor to validate

    Returns:
        ValidationResult with detected anomalies
    """
    validator = DescriptorValidator()
    return validator.validate(descriptor)
