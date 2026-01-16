"""
USB Event Interceptor - Layer 1.

Captures USB device enumeration events and descriptor data
before the operating system binds drivers.
"""

from sentinel.interceptor.constants import (
    USBClass,
    SecurityRisk,
    get_class_info,
    get_class_name,
    get_class_risk,
    is_high_risk_class,
    get_vendor_info,
    is_trusted_vendor,
    is_suspicious_vendor,
)
from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
    create_test_descriptor,
    extract_device_info,
)
from sentinel.interceptor.events import (
    EventDispatcher,
    EventProcessor,
    EventQueue,
    ProcessedEvent,
)
from sentinel.interceptor.linux import (
    DeviceAuthorizer,
    EventType,
    USBEnumerator,
    USBEvent,
    USBInterceptor,
    USBMonitor,
    get_platform_interceptor,
)
from sentinel.interceptor.validator import (
    Anomaly,
    AnomalyType,
    DescriptorValidator,
    Severity,
    ValidationResult,
    validate_descriptor,
)

__all__ = [
    # Constants
    "USBClass",
    "SecurityRisk",
    "get_class_info",
    "get_class_name",
    "get_class_risk",
    "is_high_risk_class",
    "get_vendor_info",
    "is_trusted_vendor",
    "is_suspicious_vendor",
    # Descriptors
    "DeviceDescriptor",
    "InterfaceDescriptor",
    "EndpointDescriptor",
    "create_test_descriptor",
    "extract_device_info",
    # Events
    "EventDispatcher",
    "EventProcessor",
    "EventQueue",
    "ProcessedEvent",
    # Linux interceptor
    "DeviceAuthorizer",
    "EventType",
    "USBEnumerator",
    "USBEvent",
    "USBInterceptor",
    "USBMonitor",
    "get_platform_interceptor",
    # Validator
    "Anomaly",
    "AnomalyType",
    "DescriptorValidator",
    "Severity",
    "ValidationResult",
    "validate_descriptor",
]
