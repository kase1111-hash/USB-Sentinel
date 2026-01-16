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

__all__ = [
    "DeviceDescriptor",
    "InterfaceDescriptor",
    "EndpointDescriptor",
    "extract_device_info",
]
