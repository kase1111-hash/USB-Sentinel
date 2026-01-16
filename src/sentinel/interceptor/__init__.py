"""
USB Event Interceptor - Layer 1.

Captures USB device enumeration events and descriptor data
before the operating system binds drivers.
"""

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
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

__all__ = [
    # Descriptors
    "DeviceDescriptor",
    "InterfaceDescriptor",
    "EndpointDescriptor",
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
]
