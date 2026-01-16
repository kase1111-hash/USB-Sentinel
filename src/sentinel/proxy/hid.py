"""
HID behavior analyzer for detecting malicious keystroke patterns.

Analyzes HID traffic to detect BadUSB, Rubber Ducky, and other
keystroke injection attacks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any

from sentinel.proxy.capture import Direction, TransferType, USBPacket


logger = logging.getLogger(__name__)


class ModifierKey(IntFlag):
    """USB HID modifier key flags."""

    NONE = 0x00
    LEFT_CTRL = 0x01
    LEFT_SHIFT = 0x02
    LEFT_ALT = 0x04
    LEFT_GUI = 0x08  # Windows/Command key
    RIGHT_CTRL = 0x10
    RIGHT_SHIFT = 0x20
    RIGHT_ALT = 0x40
    RIGHT_GUI = 0x80

    CTRL = LEFT_CTRL | RIGHT_CTRL
    SHIFT = LEFT_SHIFT | RIGHT_SHIFT
    ALT = LEFT_ALT | RIGHT_ALT
    GUI = LEFT_GUI | RIGHT_GUI


# USB HID keyboard scan codes to ASCII characters
# Based on USB HID Usage Tables 1.12
HID_KEYCODE_MAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
    0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4', 0x22: '5',
    0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n',  # Enter
    0x29: '\x1b',  # Escape
    0x2A: '\b',  # Backspace
    0x2B: '\t',  # Tab
    0x2C: ' ',   # Space
    0x2D: '-', 0x2E: '=', 0x2F: '[', 0x30: ']', 0x31: '\\',
    0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
}

# Shifted keycode map
HID_KEYCODE_MAP_SHIFTED = {
    0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E', 0x09: 'F',
    0x0A: 'G', 0x0B: 'H', 0x0C: 'I', 0x0D: 'J', 0x0E: 'K', 0x0F: 'L',
    0x10: 'M', 0x11: 'N', 0x12: 'O', 0x13: 'P', 0x14: 'Q', 0x15: 'R',
    0x16: 'S', 0x17: 'T', 0x18: 'U', 0x19: 'V', 0x1A: 'W', 0x1B: 'X',
    0x1C: 'Y', 0x1D: 'Z',
    0x1E: '!', 0x1F: '@', 0x20: '#', 0x21: '$', 0x22: '%',
    0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')',
    0x2D: '_', 0x2E: '+', 0x2F: '{', 0x30: '}', 0x31: '|',
    0x33: ':', 0x34: '"', 0x35: '~', 0x36: '<', 0x37: '>', 0x38: '?',
}

# Special key names
SPECIAL_KEYS = {
    0x28: "[ENTER]",
    0x29: "[ESC]",
    0x2A: "[BACKSPACE]",
    0x2B: "[TAB]",
    0x39: "[CAPS]",
    0x3A: "[F1]", 0x3B: "[F2]", 0x3C: "[F3]", 0x3D: "[F4]",
    0x3E: "[F5]", 0x3F: "[F6]", 0x40: "[F7]", 0x41: "[F8]",
    0x42: "[F9]", 0x43: "[F10]", 0x44: "[F11]", 0x45: "[F12]",
    0x46: "[PRTSC]", 0x47: "[SCROLL]", 0x48: "[PAUSE]",
    0x49: "[INSERT]", 0x4A: "[HOME]", 0x4B: "[PGUP]",
    0x4C: "[DELETE]", 0x4D: "[END]", 0x4E: "[PGDN]",
    0x4F: "[RIGHT]", 0x50: "[LEFT]", 0x51: "[DOWN]", 0x52: "[UP]",
}


@dataclass
class Keystroke:
    """Represents a single keystroke event."""

    timestamp: float
    modifier: ModifierKey
    keycode: int
    is_press: bool  # True for key press, False for release

    @property
    def char(self) -> str | None:
        """Get character for this keystroke."""
        if self.keycode in SPECIAL_KEYS:
            return SPECIAL_KEYS[self.keycode]
        if self.modifier & ModifierKey.SHIFT:
            return HID_KEYCODE_MAP_SHIFTED.get(self.keycode)
        return HID_KEYCODE_MAP.get(self.keycode)

    @property
    def modifier_names(self) -> list[str]:
        """Get list of active modifier names."""
        names = []
        if self.modifier & ModifierKey.CTRL:
            names.append("CTRL")
        if self.modifier & ModifierKey.SHIFT:
            names.append("SHIFT")
        if self.modifier & ModifierKey.ALT:
            names.append("ALT")
        if self.modifier & ModifierKey.GUI:
            names.append("GUI")
        return names


@dataclass
class KeystrokeSequence:
    """Represents a sequence of keystrokes with timing."""

    keystrokes: list[Keystroke] = field(default_factory=list)

    @property
    def intervals(self) -> list[float]:
        """Get intervals between keystrokes in milliseconds."""
        if len(self.keystrokes) < 2:
            return []
        intervals = []
        for i in range(1, len(self.keystrokes)):
            delta = (
                self.keystrokes[i].timestamp - self.keystrokes[i - 1].timestamp
            ) * 1000  # Convert to ms
            intervals.append(delta)
        return intervals

    @property
    def avg_interval_ms(self) -> float:
        """Get average interval in milliseconds."""
        intervals = self.intervals
        if not intervals:
            return 0.0
        return sum(intervals) / len(intervals)

    @property
    def min_interval_ms(self) -> float:
        """Get minimum interval in milliseconds."""
        intervals = self.intervals
        if not intervals:
            return 0.0
        return min(intervals)

    @property
    def max_interval_ms(self) -> float:
        """Get maximum interval in milliseconds."""
        intervals = self.intervals
        if not intervals:
            return 0.0
        return max(intervals)

    @property
    def duration_ms(self) -> float:
        """Get total duration of sequence in milliseconds."""
        if len(self.keystrokes) < 2:
            return 0.0
        return (
            self.keystrokes[-1].timestamp - self.keystrokes[0].timestamp
        ) * 1000


@dataclass
class KeystrokeAnalysis:
    """Complete analysis of HID keystroke traffic."""

    # Timing analysis
    avg_interval_ms: float
    min_interval_ms: float
    max_interval_ms: float
    total_duration_ms: float

    # Key analysis
    keystroke_count: int
    unique_keycodes: int
    modifier_sequences: list[str]
    decoded_text: str

    # Risk indicators
    is_suspicious: bool
    suspicion_reasons: list[str]
    risk_score: int  # 0-100

    # Raw data
    keystrokes: list[Keystroke] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API/logging."""
        return {
            "avg_interval_ms": self.avg_interval_ms,
            "min_interval_ms": self.min_interval_ms,
            "max_interval_ms": self.max_interval_ms,
            "total_duration_ms": self.total_duration_ms,
            "keystroke_count": self.keystroke_count,
            "unique_keycodes": self.unique_keycodes,
            "modifier_sequences": self.modifier_sequences,
            "decoded_text": self.decoded_text[:100] if self.decoded_text else "",
            "is_suspicious": self.is_suspicious,
            "suspicion_reasons": self.suspicion_reasons,
            "risk_score": self.risk_score,
        }


# Suspicious modifier sequences (common in attacks)
DANGEROUS_MODIFIER_COMBOS = [
    (ModifierKey.GUI, 0x15),  # GUI+R (Run dialog)
    (ModifierKey.ALT, 0x3D),  # ALT+F4 (Close window)
    (ModifierKey.CTRL | ModifierKey.ALT, 0x4C),  # Ctrl+Alt+Delete
    (ModifierKey.GUI, 0x07),  # GUI+D (Show desktop)
    (ModifierKey.GUI, 0x08),  # GUI+E (Explorer)
    (ModifierKey.CTRL | ModifierKey.SHIFT, 0x29),  # Ctrl+Shift+Esc (Task Manager)
]

# Suspicious command patterns in decoded text
SUSPICIOUS_PATTERNS = [
    "powershell",
    "cmd.exe",
    "wget ",
    "curl ",
    "bash ",
    "/bin/sh",
    "invoke-",
    "iex(",
    "downloadstring",
    "bypass",
    "-nop ",
    "-enc ",
    "hidden",
    "new-object",
]


def extract_keystrokes(packets: list[USBPacket]) -> list[Keystroke]:
    """
    Extract keystroke events from USB packets.

    Args:
        packets: List of USB packets (HID reports)

    Returns:
        List of Keystroke events
    """
    keystrokes = []
    prev_keycodes: set[int] = set()

    for packet in packets:
        # Filter for HID interrupt IN packets
        if packet.transfer_type != TransferType.INTERRUPT:
            continue
        if packet.direction != Direction.IN:
            continue
        if len(packet.data) < 3:
            continue

        # Parse HID keyboard report
        # Format: [modifier, reserved, keycode1, keycode2, ..., keycode6]
        modifier = ModifierKey(packet.data[0])
        current_keycodes = set(
            code for code in packet.data[2:8] if code != 0
        )

        # Detect new key presses
        for keycode in current_keycodes - prev_keycodes:
            keystrokes.append(Keystroke(
                timestamp=packet.timestamp,
                modifier=modifier,
                keycode=keycode,
                is_press=True,
            ))

        # Detect key releases
        for keycode in prev_keycodes - current_keycodes:
            keystrokes.append(Keystroke(
                timestamp=packet.timestamp,
                modifier=modifier,
                keycode=keycode,
                is_press=False,
            ))

        prev_keycodes = current_keycodes

    return keystrokes


def decode_keystrokes(keystrokes: list[Keystroke]) -> str:
    """
    Decode keystrokes to text.

    Args:
        keystrokes: List of keystroke events

    Returns:
        Decoded text string
    """
    text = []

    for ks in keystrokes:
        if not ks.is_press:
            continue

        char = ks.char
        if char:
            text.append(char)

    return "".join(text)


def detect_modifier_patterns(keystrokes: list[Keystroke]) -> list[str]:
    """
    Detect dangerous modifier key sequences.

    Args:
        keystrokes: List of keystroke events

    Returns:
        List of detected patterns (e.g., ["GUI+R", "ALT+F4"])
    """
    patterns = []

    for ks in keystrokes:
        if not ks.is_press:
            continue

        # Build modifier string
        mod_str = "+".join(ks.modifier_names) if ks.modifier_names else ""

        # Check for dangerous combos
        for danger_mod, danger_key in DANGEROUS_MODIFIER_COMBOS:
            if ks.modifier == danger_mod and ks.keycode == danger_key:
                key_char = HID_KEYCODE_MAP.get(danger_key, f"0x{danger_key:02X}")
                pattern = f"{mod_str}+{key_char}" if mod_str else key_char
                if pattern not in patterns:
                    patterns.append(pattern)

        # Check for any GUI key combo (common in attacks)
        if ks.modifier & ModifierKey.GUI:
            key_char = HID_KEYCODE_MAP.get(ks.keycode, f"0x{ks.keycode:02X}")
            pattern = f"GUI+{key_char}"
            if pattern not in patterns:
                patterns.append(pattern)

    return patterns


def analyze_hid_traffic(
    packets: list[USBPacket],
    superhuman_threshold_ms: float = 10.0,
    rapid_threshold_ms: float = 30.0,
) -> KeystrokeAnalysis:
    """
    Analyze HID traffic for suspicious patterns.

    Detects:
    - Superhuman typing speeds (< 10ms between keys)
    - Rapid typing (< 30ms suggests scripted input)
    - Dangerous modifier sequences
    - Suspicious command patterns

    Args:
        packets: List of captured USB packets
        superhuman_threshold_ms: Threshold for superhuman typing detection
        rapid_threshold_ms: Threshold for rapid typing detection

    Returns:
        KeystrokeAnalysis with findings
    """
    # Extract keystrokes
    keystrokes = extract_keystrokes(packets)
    press_keystrokes = [ks for ks in keystrokes if ks.is_press]

    if not press_keystrokes:
        return KeystrokeAnalysis(
            avg_interval_ms=0,
            min_interval_ms=0,
            max_interval_ms=0,
            total_duration_ms=0,
            keystroke_count=0,
            unique_keycodes=0,
            modifier_sequences=[],
            decoded_text="",
            is_suspicious=False,
            suspicion_reasons=[],
            risk_score=0,
            keystrokes=keystrokes,
        )

    # Create sequence for timing analysis
    sequence = KeystrokeSequence(keystrokes=press_keystrokes)

    # Decode text
    decoded = decode_keystrokes(press_keystrokes)

    # Detect modifier patterns
    modifier_sequences = detect_modifier_patterns(press_keystrokes)

    # Analyze for suspicion
    suspicion_reasons = []
    risk_score = 0

    # Check for superhuman typing
    if sequence.min_interval_ms > 0 and sequence.min_interval_ms < superhuman_threshold_ms:
        suspicion_reasons.append(
            f"Superhuman typing speed detected ({sequence.min_interval_ms:.1f}ms between keys)"
        )
        risk_score += 40

    # Check for rapid typing
    elif sequence.avg_interval_ms > 0 and sequence.avg_interval_ms < rapid_threshold_ms:
        suspicion_reasons.append(
            f"Rapid scripted typing detected (avg {sequence.avg_interval_ms:.1f}ms)"
        )
        risk_score += 25

    # Check for dangerous modifier combos
    if modifier_sequences:
        suspicion_reasons.append(
            f"Dangerous modifier sequences: {', '.join(modifier_sequences)}"
        )
        risk_score += 15 * len(modifier_sequences)

    # Check decoded text for suspicious patterns
    decoded_lower = decoded.lower()
    found_patterns = [
        p for p in SUSPICIOUS_PATTERNS if p in decoded_lower
    ]
    if found_patterns:
        suspicion_reasons.append(
            f"Suspicious commands detected: {', '.join(found_patterns)}"
        )
        risk_score += 20 * len(found_patterns)

    # High keystroke volume in short time
    keystrokes_per_second = 0
    if sequence.duration_ms > 0:
        keystrokes_per_second = len(press_keystrokes) / (sequence.duration_ms / 1000)
        if keystrokes_per_second > 20:  # 20 keys/second is very fast
            suspicion_reasons.append(
                f"High keystroke rate: {keystrokes_per_second:.1f}/sec"
            )
            risk_score += 15

    # Cap risk score
    risk_score = min(100, risk_score)

    return KeystrokeAnalysis(
        avg_interval_ms=sequence.avg_interval_ms,
        min_interval_ms=sequence.min_interval_ms,
        max_interval_ms=sequence.max_interval_ms,
        total_duration_ms=sequence.duration_ms,
        keystroke_count=len(press_keystrokes),
        unique_keycodes=len(set(ks.keycode for ks in press_keystrokes)),
        modifier_sequences=modifier_sequences,
        decoded_text=decoded,
        is_suspicious=len(suspicion_reasons) > 0,
        suspicion_reasons=suspicion_reasons,
        risk_score=risk_score,
        keystrokes=keystrokes,
    )


def create_mock_keystrokes(
    text: str,
    interval_ms: float = 50.0,
    include_gui_r: bool = False,
) -> list[Keystroke]:
    """
    Create mock keystrokes for testing.

    Args:
        text: Text to convert to keystrokes
        interval_ms: Interval between keystrokes
        include_gui_r: Include GUI+R at start (attack pattern)

    Returns:
        List of mock keystrokes
    """
    keystrokes = []
    timestamp = 0.0

    # Reverse lookup map
    char_to_keycode = {v: k for k, v in HID_KEYCODE_MAP.items()}
    char_to_keycode_shifted = {v: k for k, v in HID_KEYCODE_MAP_SHIFTED.items()}

    # Add GUI+R if requested
    if include_gui_r:
        keystrokes.append(Keystroke(
            timestamp=timestamp,
            modifier=ModifierKey.LEFT_GUI,
            keycode=0x15,  # 'r'
            is_press=True,
        ))
        timestamp += interval_ms / 1000

    # Convert text to keystrokes
    for char in text:
        keycode = char_to_keycode.get(char.lower())
        modifier = ModifierKey.NONE

        if keycode is None:
            keycode = char_to_keycode_shifted.get(char)
            if keycode:
                modifier = ModifierKey.LEFT_SHIFT

        if keycode is None:
            continue

        keystrokes.append(Keystroke(
            timestamp=timestamp,
            modifier=modifier,
            keycode=keycode,
            is_press=True,
        ))
        timestamp += interval_ms / 1000

        # Add release
        keystrokes.append(Keystroke(
            timestamp=timestamp + 0.01,
            modifier=ModifierKey.NONE,
            keycode=keycode,
            is_press=False,
        ))

    return keystrokes


class HIDAnalyzer:
    """
    Stateful HID traffic analyzer.

    Maintains state across multiple analysis sessions and tracks
    historical patterns.
    """

    def __init__(
        self,
        superhuman_threshold_ms: float = 10.0,
        rapid_threshold_ms: float = 30.0,
    ) -> None:
        """Initialize analyzer with thresholds."""
        self.superhuman_threshold_ms = superhuman_threshold_ms
        self.rapid_threshold_ms = rapid_threshold_ms

        self._analysis_count = 0
        self._suspicious_count = 0
        self._total_keystrokes = 0

    def analyze(self, packets: list[USBPacket]) -> KeystrokeAnalysis:
        """
        Analyze HID traffic.

        Args:
            packets: USB packets to analyze

        Returns:
            KeystrokeAnalysis results
        """
        result = analyze_hid_traffic(
            packets,
            superhuman_threshold_ms=self.superhuman_threshold_ms,
            rapid_threshold_ms=self.rapid_threshold_ms,
        )

        # Update statistics
        self._analysis_count += 1
        if result.is_suspicious:
            self._suspicious_count += 1
        self._total_keystrokes += result.keystroke_count

        return result

    def get_statistics(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "analysis_count": self._analysis_count,
            "suspicious_count": self._suspicious_count,
            "total_keystrokes": self._total_keystrokes,
            "superhuman_threshold_ms": self.superhuman_threshold_ms,
            "rapid_threshold_ms": self.rapid_threshold_ms,
        }

    def reset_statistics(self) -> None:
        """Reset statistics."""
        self._analysis_count = 0
        self._suspicious_count = 0
        self._total_keystrokes = 0
