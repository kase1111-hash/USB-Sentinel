"""
Virtual USB Proxy - Layer 4.

Provides sandboxed device inspection by routing device traffic
through a controlled environment for behavioral analysis.
"""

from sentinel.proxy.capture import (
    CaptureFile,
    CaptureSession,
    Direction,
    MockUSBTrafficCapture,
    TransferType,
    URBType,
    USBPacket,
    USBTrafficCapture,
    create_capture,
)
from sentinel.proxy.hid import (
    HIDAnalyzer,
    Keystroke,
    KeystrokeAnalysis,
    KeystrokeSequence,
    ModifierKey,
    analyze_hid_traffic,
    create_mock_keystrokes,
    decode_keystrokes,
    detect_modifier_patterns,
    extract_keystrokes,
)
from sentinel.proxy.sandbox import (
    DeviceSandbox,
    KeystrokeBuffer,
    ModifierBlocker,
    ReEnumerationDetector,
    SandboxAction,
    SandboxConfig,
    SandboxEvent,
    SandboxManager,
    SandboxRule,
    create_attack_detection_rules,
)
from sentinel.proxy.usbip import (
    MockUSBIPProxy,
    ProxyDevice,
    ProxyStatus,
    USBIPConfig,
    USBIPError,
    USBIPProxy,
    create_proxy,
)

__all__ = [
    # USB/IP Proxy
    "USBIPProxy",
    "MockUSBIPProxy",
    "USBIPConfig",
    "USBIPError",
    "ProxyDevice",
    "ProxyStatus",
    "create_proxy",
    # Traffic Capture
    "USBTrafficCapture",
    "MockUSBTrafficCapture",
    "USBPacket",
    "CaptureFile",
    "CaptureSession",
    "URBType",
    "TransferType",
    "Direction",
    "create_capture",
    # HID Analysis
    "HIDAnalyzer",
    "KeystrokeAnalysis",
    "Keystroke",
    "KeystrokeSequence",
    "ModifierKey",
    "analyze_hid_traffic",
    "extract_keystrokes",
    "decode_keystrokes",
    "detect_modifier_patterns",
    "create_mock_keystrokes",
    # Sandbox
    "DeviceSandbox",
    "SandboxManager",
    "SandboxConfig",
    "SandboxAction",
    "SandboxRule",
    "SandboxEvent",
    "KeystrokeBuffer",
    "ModifierBlocker",
    "ReEnumerationDetector",
    "create_attack_detection_rules",
]
