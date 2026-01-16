"""
USB device sandbox behaviors.

Provides protective behaviors for sandboxed USB devices:
- Keystroke throttling to prevent rapid injection
- Modifier sequence blocking
- Re-enumeration detection
- Traffic analysis triggers
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable


logger = logging.getLogger(__name__)


class SandboxAction(Enum):
    """Actions that can be taken on sandboxed traffic."""

    ALLOW = auto()      # Allow traffic through
    BLOCK = auto()      # Block traffic completely
    DELAY = auto()      # Delay traffic (throttle)
    LOG = auto()        # Log and allow
    ALERT = auto()      # Alert and allow


@dataclass
class SandboxRule:
    """Rule for sandbox behavior."""

    name: str
    condition: Callable[[bytes], bool]
    action: SandboxAction
    delay_ms: float = 0.0
    priority: int = 0

    def matches(self, data: bytes) -> bool:
        """Check if rule matches the data."""
        try:
            return self.condition(data)
        except Exception:
            return False


@dataclass
class SandboxEvent:
    """Event recorded by sandbox."""

    timestamp: datetime
    event_type: str
    action: SandboxAction
    rule_name: str | None
    data_preview: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class KeystrokeBuffer:
    """Buffer for keystroke throttling."""

    max_size: int = 100
    max_rate_per_second: float = 20.0
    window_ms: float = 1000.0

    _keystrokes: deque = field(default_factory=lambda: deque(maxlen=100))
    _timestamps: deque = field(default_factory=lambda: deque(maxlen=100))

    def add(self, data: bytes, timestamp: float) -> tuple[bool, float]:
        """
        Add keystroke to buffer.

        Args:
            data: Keystroke data
            timestamp: Event timestamp

        Returns:
            Tuple of (should_allow, delay_ms)
        """
        self._keystrokes.append(data)
        self._timestamps.append(timestamp)

        # Calculate current rate
        window_start = timestamp - (self.window_ms / 1000.0)
        recent = [t for t in self._timestamps if t >= window_start]

        if len(recent) > 1:
            duration = recent[-1] - recent[0]
            if duration > 0:
                rate = (len(recent) - 1) / duration
                if rate > self.max_rate_per_second:
                    # Need to throttle - calculate delay
                    target_interval = 1.0 / self.max_rate_per_second
                    actual_interval = duration / (len(recent) - 1)
                    delay = (target_interval - actual_interval) * 1000
                    return True, max(0, delay)

        return True, 0.0

    def clear(self) -> None:
        """Clear the buffer."""
        self._keystrokes.clear()
        self._timestamps.clear()


class ModifierBlocker:
    """Blocks dangerous modifier key combinations."""

    # Modifier byte is first byte of HID keyboard report
    # Dangerous combos: GUI+R, GUI+any, Ctrl+Alt+Del pattern
    BLOCKED_PATTERNS = [
        # (modifier_mask, modifier_value, keycode_mask, keycode_value)
        (0x88, 0x08, 0xFF, 0x15),  # GUI+R
        (0x88, 0x08, 0xFF, 0x07),  # GUI+D
        (0x88, 0x08, 0xFF, 0x08),  # GUI+E
        (0x88, 0x88, 0xFF, 0x00),  # Both GUI keys
    ]

    def __init__(self, enabled: bool = True) -> None:
        """Initialize blocker."""
        self.enabled = enabled
        self._blocked_count = 0

    def check(self, data: bytes) -> tuple[bool, str | None]:
        """
        Check if HID report should be blocked.

        Args:
            data: HID keyboard report (8 bytes)

        Returns:
            Tuple of (should_block, reason)
        """
        if not self.enabled or len(data) < 3:
            return False, None

        modifier = data[0]
        keycodes = data[2:8]

        for mod_mask, mod_val, key_mask, key_val in self.BLOCKED_PATTERNS:
            if (modifier & mod_mask) == mod_val:
                for keycode in keycodes:
                    if keycode != 0 and (keycode & key_mask) == key_val:
                        self._blocked_count += 1
                        return True, f"Blocked modifier combo: 0x{modifier:02X}+0x{keycode:02X}"

        return False, None

    def get_blocked_count(self) -> int:
        """Get number of blocked combos."""
        return self._blocked_count


class ReEnumerationDetector:
    """Detects USB device re-enumeration attempts."""

    def __init__(
        self,
        max_resets_per_minute: int = 3,
        detection_window_sec: float = 60.0,
    ) -> None:
        """
        Initialize detector.

        Args:
            max_resets_per_minute: Maximum allowed resets
            detection_window_sec: Window for counting resets
        """
        self.max_resets = max_resets_per_minute
        self.window_sec = detection_window_sec
        self._reset_times: deque = deque()
        self._detected_count = 0

    def record_reset(self) -> bool:
        """
        Record a device reset event.

        Returns:
            True if this appears to be an attack
        """
        now = time.time()
        self._reset_times.append(now)

        # Clean old entries
        window_start = now - self.window_sec
        while self._reset_times and self._reset_times[0] < window_start:
            self._reset_times.popleft()

        # Check for attack
        if len(self._reset_times) > self.max_resets:
            self._detected_count += 1
            logger.warning(
                "Re-enumeration attack detected: %d resets in %.0fs",
                len(self._reset_times),
                self.window_sec,
            )
            return True

        return False

    def get_reset_count(self) -> int:
        """Get recent reset count."""
        now = time.time()
        window_start = now - self.window_sec
        return sum(1 for t in self._reset_times if t >= window_start)

    def get_detection_count(self) -> int:
        """Get number of attack detections."""
        return self._detected_count


@dataclass
class SandboxConfig:
    """Configuration for device sandbox."""

    # Throttling
    enable_throttling: bool = True
    max_keystrokes_per_second: float = 20.0
    throttle_delay_ms: float = 50.0

    # Blocking
    enable_modifier_blocking: bool = True
    blocked_modifier_combos: list[tuple[int, int]] = field(
        default_factory=lambda: [
            (0x08, 0x15),  # GUI+R
            (0x08, 0x07),  # GUI+D
        ]
    )

    # Re-enumeration
    enable_reenum_detection: bool = True
    max_resets_per_minute: int = 3

    # Alerting
    alert_on_block: bool = True
    alert_on_throttle: bool = False

    # Logging
    log_all_traffic: bool = False
    max_events: int = 1000


class DeviceSandbox:
    """
    Sandbox environment for a USB device.

    Provides traffic filtering, throttling, and behavioral analysis
    for devices that require sandbox inspection.
    """

    def __init__(
        self,
        device_id: str,
        config: SandboxConfig | None = None,
    ) -> None:
        """
        Initialize sandbox for a device.

        Args:
            device_id: Identifier for the device
            config: Sandbox configuration
        """
        self.device_id = device_id
        self.config = config or SandboxConfig()

        # Components
        self._keystroke_buffer = KeystrokeBuffer(
            max_rate_per_second=self.config.max_keystrokes_per_second,
        )
        self._modifier_blocker = ModifierBlocker(
            enabled=self.config.enable_modifier_blocking,
        )
        self._reenum_detector = ReEnumerationDetector(
            max_resets_per_minute=self.config.max_resets_per_minute,
        )

        # Custom rules
        self._rules: list[SandboxRule] = []

        # Event log
        self._events: deque[SandboxEvent] = deque(maxlen=self.config.max_events)

        # Callbacks
        self._on_block: Callable[[SandboxEvent], None] | None = None
        self._on_alert: Callable[[SandboxEvent], None] | None = None

        # State
        self._active = True
        self._start_time = datetime.utcnow()

        # Statistics
        self._total_packets = 0
        self._blocked_packets = 0
        self._throttled_packets = 0
        self._total_delay_ms = 0.0

        logger.info("Sandbox created for device %s", device_id)

    def add_rule(self, rule: SandboxRule) -> None:
        """Add a custom sandbox rule."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: -r.priority)

    def set_block_callback(
        self, callback: Callable[[SandboxEvent], None]
    ) -> None:
        """Set callback for block events."""
        self._on_block = callback

    def set_alert_callback(
        self, callback: Callable[[SandboxEvent], None]
    ) -> None:
        """Set callback for alert events."""
        self._on_alert = callback

    def process_hid_report(
        self,
        data: bytes,
        timestamp: float | None = None,
    ) -> tuple[SandboxAction, bytes, float]:
        """
        Process an HID report through the sandbox.

        Args:
            data: HID report data
            timestamp: Event timestamp (uses current time if None)

        Returns:
            Tuple of (action, modified_data, delay_ms)
        """
        if not self._active:
            return SandboxAction.ALLOW, data, 0.0

        timestamp = timestamp or time.time()
        self._total_packets += 1

        # Check custom rules first
        for rule in self._rules:
            if rule.matches(data):
                event = SandboxEvent(
                    timestamp=datetime.utcnow(),
                    event_type="rule_match",
                    action=rule.action,
                    rule_name=rule.name,
                    data_preview=data[:16].hex(),
                )
                self._events.append(event)

                if rule.action == SandboxAction.BLOCK:
                    self._blocked_packets += 1
                    if self._on_block:
                        self._on_block(event)
                    return SandboxAction.BLOCK, b"", 0.0

                if rule.action == SandboxAction.DELAY:
                    self._throttled_packets += 1
                    self._total_delay_ms += rule.delay_ms
                    return SandboxAction.DELAY, data, rule.delay_ms

        # Check modifier blocking
        should_block, reason = self._modifier_blocker.check(data)
        if should_block:
            self._blocked_packets += 1
            event = SandboxEvent(
                timestamp=datetime.utcnow(),
                event_type="modifier_block",
                action=SandboxAction.BLOCK,
                rule_name="modifier_blocker",
                data_preview=data[:16].hex(),
                details={"reason": reason},
            )
            self._events.append(event)

            if self._on_block:
                self._on_block(event)

            logger.warning("Sandbox blocked modifier: %s", reason)
            return SandboxAction.BLOCK, b"", 0.0

        # Check throttling
        if self.config.enable_throttling:
            should_allow, delay = self._keystroke_buffer.add(data, timestamp)
            if delay > 0:
                self._throttled_packets += 1
                self._total_delay_ms += delay

                if self.config.alert_on_throttle:
                    event = SandboxEvent(
                        timestamp=datetime.utcnow(),
                        event_type="throttle",
                        action=SandboxAction.DELAY,
                        rule_name="keystroke_throttle",
                        data_preview=data[:16].hex(),
                        details={"delay_ms": delay},
                    )
                    self._events.append(event)

                return SandboxAction.DELAY, data, delay

        # Log if configured
        if self.config.log_all_traffic:
            event = SandboxEvent(
                timestamp=datetime.utcnow(),
                event_type="traffic",
                action=SandboxAction.LOG,
                rule_name=None,
                data_preview=data[:16].hex(),
            )
            self._events.append(event)

        return SandboxAction.ALLOW, data, 0.0

    def record_device_reset(self) -> bool:
        """
        Record a device reset/re-enumeration.

        Returns:
            True if this appears to be an attack
        """
        if not self.config.enable_reenum_detection:
            return False

        is_attack = self._reenum_detector.record_reset()

        if is_attack:
            event = SandboxEvent(
                timestamp=datetime.utcnow(),
                event_type="reenum_attack",
                action=SandboxAction.ALERT,
                rule_name="reenum_detector",
                data_preview="",
                details={
                    "reset_count": self._reenum_detector.get_reset_count(),
                },
            )
            self._events.append(event)

            if self._on_alert:
                self._on_alert(event)

        return is_attack

    def get_events(
        self,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[SandboxEvent]:
        """
        Get sandbox events.

        Args:
            event_type: Filter by event type
            limit: Maximum events to return

        Returns:
            List of events
        """
        events = list(self._events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def get_statistics(self) -> dict[str, Any]:
        """Get sandbox statistics."""
        return {
            "device_id": self.device_id,
            "active": self._active,
            "start_time": self._start_time.isoformat(),
            "total_packets": self._total_packets,
            "blocked_packets": self._blocked_packets,
            "throttled_packets": self._throttled_packets,
            "total_delay_ms": self._total_delay_ms,
            "modifier_blocks": self._modifier_blocker.get_blocked_count(),
            "reenum_detections": self._reenum_detector.get_detection_count(),
            "recent_resets": self._reenum_detector.get_reset_count(),
            "event_count": len(self._events),
            "rule_count": len(self._rules),
        }

    def activate(self) -> None:
        """Activate the sandbox."""
        self._active = True
        logger.info("Sandbox activated for %s", self.device_id)

    def deactivate(self) -> None:
        """Deactivate the sandbox (pass-through mode)."""
        self._active = False
        logger.info("Sandbox deactivated for %s", self.device_id)

    def reset(self) -> None:
        """Reset sandbox state."""
        self._keystroke_buffer.clear()
        self._events.clear()
        self._total_packets = 0
        self._blocked_packets = 0
        self._throttled_packets = 0
        self._total_delay_ms = 0.0
        logger.info("Sandbox reset for %s", self.device_id)


class SandboxManager:
    """
    Manages multiple device sandboxes.

    Provides centralized management and monitoring of sandboxed devices.
    """

    def __init__(self, default_config: SandboxConfig | None = None) -> None:
        """
        Initialize sandbox manager.

        Args:
            default_config: Default configuration for new sandboxes
        """
        self.default_config = default_config or SandboxConfig()
        self._sandboxes: dict[str, DeviceSandbox] = {}
        self._lock = threading.Lock()

    def create_sandbox(
        self,
        device_id: str,
        config: SandboxConfig | None = None,
    ) -> DeviceSandbox:
        """
        Create or get a sandbox for a device.

        Args:
            device_id: Device identifier
            config: Optional custom configuration

        Returns:
            DeviceSandbox instance
        """
        with self._lock:
            if device_id in self._sandboxes:
                return self._sandboxes[device_id]

            sandbox = DeviceSandbox(
                device_id=device_id,
                config=config or self.default_config,
            )
            self._sandboxes[device_id] = sandbox
            return sandbox

    def get_sandbox(self, device_id: str) -> DeviceSandbox | None:
        """Get sandbox for a device."""
        return self._sandboxes.get(device_id)

    def remove_sandbox(self, device_id: str) -> bool:
        """
        Remove a sandbox.

        Args:
            device_id: Device identifier

        Returns:
            True if sandbox was removed
        """
        with self._lock:
            if device_id in self._sandboxes:
                self._sandboxes[device_id].deactivate()
                del self._sandboxes[device_id]
                return True
            return False

    def get_all_sandboxes(self) -> list[DeviceSandbox]:
        """Get all active sandboxes."""
        return list(self._sandboxes.values())

    def get_statistics(self) -> dict[str, Any]:
        """Get aggregated statistics."""
        total_packets = 0
        total_blocked = 0
        total_throttled = 0

        for sandbox in self._sandboxes.values():
            stats = sandbox.get_statistics()
            total_packets += stats["total_packets"]
            total_blocked += stats["blocked_packets"]
            total_throttled += stats["throttled_packets"]

        return {
            "sandbox_count": len(self._sandboxes),
            "total_packets": total_packets,
            "total_blocked": total_blocked,
            "total_throttled": total_throttled,
            "device_ids": list(self._sandboxes.keys()),
        }


# Pre-built sandbox rules for common attack patterns


def rule_block_powershell(data: bytes) -> bool:
    """Block HID sequences that might be typing 'powershell'."""
    # This is a simplified check - real implementation would
    # track keystroke sequences over time
    return False  # Placeholder


def rule_detect_rapid_gui_keys(data: bytes) -> bool:
    """Detect rapid GUI key usage."""
    if len(data) < 1:
        return False
    modifier = data[0]
    return (modifier & 0x88) != 0  # Any GUI key pressed


def create_attack_detection_rules() -> list[SandboxRule]:
    """Create standard attack detection rules."""
    return [
        SandboxRule(
            name="rapid_gui_keys",
            condition=rule_detect_rapid_gui_keys,
            action=SandboxAction.LOG,
            priority=10,
        ),
    ]
