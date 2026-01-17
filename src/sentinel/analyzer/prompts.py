"""
System prompts for LLM-based USB threat analysis.

Defines constitutional bounds and structured prompts for analyzing
USB device descriptors and detecting potential security threats.
"""

from __future__ import annotations

import json
import re
from typing import Any

from sentinel.interceptor.descriptors import DeviceDescriptor


# Constitutional system prompt establishing LLM behavior boundaries
SYSTEM_PROMPT = '''You are a USB security analyst agent. Your role is to evaluate USB device descriptors for potential security threats.

## Constitutional Bounds

You MUST adhere to these inviolable rules:

1. OUTPUT FORMAT: You MUST respond with valid JSON only. No explanatory text outside JSON.
2. REQUIRED FIELDS: Your response MUST include exactly these fields:
   - "risk_score": integer 0-100
   - "verdict": one of "ALLOW", "BLOCK", or "SANDBOX"
   - "analysis": string explanation (max 500 chars)
   - "confidence": float 0.0-1.0
   - "threat_indicators": array of identified risk factors
3. SCOPE: You CANNOT recommend actions outside USB device handling
4. UNCERTAINTY: You MUST flag uncertainty (low confidence) rather than guess
5. BIAS: You MUST NOT be influenced by vendor reputation alone

## Risk Score Guidelines

- 0-25: Low risk - Common consumer devices with normal descriptors
- 26-50: Medium risk - Unusual but potentially legitimate configurations
- 51-75: High risk - Suspicious patterns requiring sandbox inspection
- 76-100: Critical - Strong indicators of malicious intent

## Key Threat Indicators

1. **BadUSB / Rubber Ducky Patterns**:
   - HID device with mass storage endpoints
   - Keyboard device with unexpected bulk endpoints
   - Generic vendor strings on HID devices

2. **Class Spoofing**:
   - Device class (0x00) with suspicious interface combinations
   - Mismatched class/subclass/protocol values
   - Multiple HID interfaces on non-composite device

3. **Firmware Manipulation Indicators**:
   - Vendor strings that don't match known VID
   - Impossible USB version for device type
   - Serial numbers with suspicious patterns

4. **Data Exfiltration Risks**:
   - Hidden mass storage on input devices
   - Unusual endpoint configurations
   - High bandwidth endpoints on low-data devices

## Response Format

```json
{
  "risk_score": <int 0-100>,
  "verdict": "<ALLOW|BLOCK|SANDBOX>",
  "analysis": "<brief explanation>",
  "confidence": <float 0.0-1.0>,
  "threat_indicators": ["indicator1", "indicator2"]
}
```'''


# Prompt template for device analysis
DEVICE_ANALYSIS_PROMPT = '''Analyze this USB device for security threats:

## Device Information

**Basic Info:**
- VID:PID: {vid}:{pid}
- Manufacturer: {manufacturer}
- Product: {product}
- Serial: {serial}

**Device Class:**
- Class: {device_class} ({device_class_name})
- Subclass: {device_subclass}
- Protocol: {device_protocol}

**Interfaces ({interface_count}):**
{interfaces}

**Device Flags:**
- Composite Device: {is_composite}
- Has HID Interface: {has_hid}
- Has Mass Storage: {has_storage}
- Has Keyboard: {has_keyboard}
- Has Mouse: {has_mouse}
- Total Endpoints: {total_endpoints}

## Historical Context
{history}

## Analysis Request

Evaluate this device considering:
1. Is the interface combination typical for this device type?
2. Are there any suspicious endpoint configurations?
3. Does the vendor information match expected patterns for VID {vid}?
4. Are there indicators of BadUSB, keystroke injection, or data exfiltration?

Provide your risk assessment in the required JSON format.'''


# Prompt for analyzing device behavior patterns
BEHAVIOR_ANALYSIS_PROMPT = '''Analyze this USB device behavioral data for anomalies:

## Device
- VID:PID: {vid}:{pid}
- Type: {device_type}

## Captured Traffic Summary
- Duration: {capture_duration_ms}ms
- Packet Count: {packet_count}
- HID Reports: {hid_report_count}

## Keystroke Analysis (if HID)
- Keystrokes Detected: {keystroke_count}
- Average Interval: {avg_interval_ms}ms
- Minimum Interval: {min_interval_ms}ms
- Modifier Keys Used: {modifier_sequences}

## Suspicious Patterns
{suspicious_patterns}

## Analysis Request

Evaluate whether this traffic pattern indicates:
1. Automated keystroke injection (superhuman typing speed < 10ms)
2. Suspicious modifier key sequences (rapid Alt+Tab, Ctrl+Shift combos)
3. Potential data exfiltration via HID
4. Re-enumeration attempts

Provide your risk assessment in the required JSON format.'''


def format_device_prompt(
    device: DeviceDescriptor,
    history: str | None = None,
) -> str:
    """
    Format the device analysis prompt with device information.

    Args:
        device: Device descriptor to analyze
        history: Optional historical context (previous sightings, etc.)

    Returns:
        Formatted prompt string
    """
    # Format interfaces
    interfaces_text = []
    for i, intf in enumerate(device.interfaces):
        intf_str = (
            f"  Interface {i}: Class={intf.interface_class} ({intf.class_name}), "
            f"Subclass={intf.interface_subclass}, Protocol={intf.interface_protocol}, "
            f"Endpoints={intf.num_endpoints}"
        )
        if intf.endpoints:
            for ep in intf.endpoints:
                intf_str += f"\n    - EP 0x{ep.address:02X}: {ep.transfer_type} {ep.direction}"
        interfaces_text.append(intf_str)

    history_text = history or "No previous history for this device."

    return DEVICE_ANALYSIS_PROMPT.format(
        vid=device.vid,
        pid=device.pid,
        manufacturer=device.manufacturer or "Not specified",
        product=device.product or "Not specified",
        serial=device.serial or "Not specified",
        device_class=device.device_class,
        device_class_name=device.class_name,
        device_subclass=device.device_subclass,
        device_protocol=device.device_protocol,
        interface_count=len(device.interfaces),
        interfaces="\n".join(interfaces_text) if interfaces_text else "  No interfaces",
        is_composite="Yes" if device.is_composite else "No",
        has_hid="Yes" if device.has_hid else "No",
        has_storage="Yes" if device.has_storage else "No",
        has_keyboard="Yes" if device.has_keyboard else "No",
        has_mouse="Yes" if device.has_mouse else "No",
        total_endpoints=device.total_endpoints,
        history=history_text,
    )


def format_behavior_prompt(
    device: DeviceDescriptor,
    traffic_data: dict[str, Any],
) -> str:
    """
    Format the behavior analysis prompt with traffic data.

    Args:
        device: Device descriptor
        traffic_data: Captured traffic analysis data

    Returns:
        Formatted prompt string
    """
    # Determine device type
    device_type = "Unknown"
    if device.has_keyboard:
        device_type = "Keyboard"
    elif device.has_mouse:
        device_type = "Mouse"
    elif device.has_hid:
        device_type = "HID Device"
    elif device.has_storage:
        device_type = "Mass Storage"

    # Format suspicious patterns
    patterns = traffic_data.get("suspicious_patterns", [])
    patterns_text = "\n".join(f"- {p}" for p in patterns) if patterns else "None detected"

    # Format modifier sequences
    modifiers = traffic_data.get("modifier_sequences", [])
    modifiers_text = ", ".join(modifiers) if modifiers else "None"

    return BEHAVIOR_ANALYSIS_PROMPT.format(
        vid=device.vid,
        pid=device.pid,
        device_type=device_type,
        capture_duration_ms=traffic_data.get("capture_duration_ms", 0),
        packet_count=traffic_data.get("packet_count", 0),
        hid_report_count=traffic_data.get("hid_report_count", 0),
        keystroke_count=traffic_data.get("keystroke_count", 0),
        avg_interval_ms=traffic_data.get("avg_interval_ms", 0),
        min_interval_ms=traffic_data.get("min_interval_ms", 0),
        modifier_sequences=modifiers_text,
        suspicious_patterns=patterns_text,
    )


def sanitize_input(text: str) -> str:
    """
    Sanitize input text to prevent prompt injection.

    Removes or escapes potentially dangerous patterns that could
    manipulate LLM behavior.

    Args:
        text: Raw input text

    Returns:
        Sanitized text safe for inclusion in prompts
    """
    if not text:
        return ""

    # Limit length
    text = text[:1000]

    # Remove control characters except common whitespace
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

    # Escape patterns that could be prompt injection attempts
    injection_patterns = [
        (r'```', '`​`​`'),  # Code blocks with zero-width spaces
        (r'\[INST\]', '[​INST]'),  # Instruction markers
        (r'\[/INST\]', '[/​INST]'),
        (r'<\|.*?\|>', ''),  # Special tokens
        (r'###\s*(System|User|Assistant)', '### \\1'),  # Role markers
        (r'Human:', 'Human​:'),  # Claude-specific
        (r'Assistant:', 'Assistant​:'),
        (r'IGNORE\s+(PREVIOUS|ABOVE|ALL)', ''),  # Direct injection attempts
        (r'(forget|ignore|disregard)\s+(everything|all|previous)', ''),
    ]

    for pattern, replacement in injection_patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text.strip()


def sanitize_device_strings(device: DeviceDescriptor) -> dict[str, str]:
    """
    Sanitize all string fields from a device descriptor.

    Args:
        device: Device descriptor with potentially untrusted strings

    Returns:
        Dictionary of sanitized string fields
    """
    return {
        "manufacturer": sanitize_input(device.manufacturer or ""),
        "product": sanitize_input(device.product or ""),
        "serial": sanitize_input(device.serial or ""),
    }


def validate_response(response_text: str) -> dict[str, Any] | None:
    """
    Validate and parse LLM response JSON.

    Ensures the response conforms to the expected schema.

    Args:
        response_text: Raw response text from LLM

    Returns:
        Parsed and validated response dict, or None if invalid
    """
    # Try to extract JSON from response
    # Sometimes LLMs add markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
    if json_match:
        response_text = json_match.group(1)
    else:
        # Try to find bare JSON object
        json_match = re.search(r'\{[^{}]*"risk_score"[^{}]*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0)

    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        return None

    # Validate required fields
    required_fields = {"risk_score", "verdict", "analysis"}
    if not all(field in data for field in required_fields):
        return None

    # Validate risk_score
    try:
        risk_score = int(data["risk_score"])
        if not 0 <= risk_score <= 100:
            return None
        data["risk_score"] = risk_score
    except (ValueError, TypeError):
        return None

    # Validate verdict
    valid_verdicts = {"ALLOW", "BLOCK", "SANDBOX"}
    verdict = str(data.get("verdict", "")).upper()
    if verdict not in valid_verdicts:
        return None
    data["verdict"] = verdict

    # Validate analysis (string)
    data["analysis"] = str(data.get("analysis", ""))[:500]

    # Validate optional confidence
    try:
        confidence = float(data.get("confidence", 1.0))
        data["confidence"] = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        data["confidence"] = 0.5  # Default to medium confidence if invalid

    # Validate optional threat_indicators
    indicators = data.get("threat_indicators", [])
    if isinstance(indicators, list):
        data["threat_indicators"] = [str(i)[:100] for i in indicators[:10]]
    else:
        data["threat_indicators"] = []

    return data


# Known vendor database for sanity checking
# VID -> expected manufacturer patterns
KNOWN_VENDORS = {
    "046d": ["logitech"],
    "8087": ["intel"],
    "1d6b": ["linux foundation"],
    "045e": ["microsoft"],
    "05ac": ["apple"],
    "04f2": ["chicony"],
    "0bda": ["realtek"],
    "8086": ["intel"],
    "0781": ["sandisk"],
    "0951": ["kingston"],
    "058f": ["alcor micro"],
    "1a86": ["qingheng", "ch340", "wch.cn"],  # Common in attack hardware
    "2341": ["arduino"],
    "10c4": ["silicon labs", "cygnal"],
}


def check_vendor_mismatch(device: DeviceDescriptor) -> str | None:
    """
    Check if manufacturer string matches expected vendor for VID.

    Args:
        device: Device descriptor to check

    Returns:
        Warning message if mismatch detected, None otherwise
    """
    vid_lower = device.vid.lower()
    if vid_lower not in KNOWN_VENDORS:
        return None

    manufacturer = (device.manufacturer or "").lower()
    if not manufacturer:
        return None

    expected_patterns = KNOWN_VENDORS[vid_lower]
    for pattern in expected_patterns:
        if pattern in manufacturer:
            return None

    return (
        f"Vendor mismatch: VID {device.vid} is registered to "
        f"{', '.join(expected_patterns)}, but manufacturer reports '{device.manufacturer}'"
    )


def build_history_context(
    device_history: list[dict[str, Any]] | None = None,
    similar_devices: list[dict[str, Any]] | None = None,
) -> str:
    """
    Build historical context string for prompt.

    Args:
        device_history: Previous events for this exact device
        similar_devices: Events for similar devices (same VID:PID)

    Returns:
        Formatted history context string
    """
    lines = []

    if device_history:
        lines.append("**This Device's History:**")
        for event in device_history[-5:]:  # Last 5 events
            lines.append(
                f"  - {event.get('timestamp', 'Unknown')}: "
                f"{event.get('event_type', 'Unknown')} "
                f"(verdict: {event.get('verdict', 'Unknown')})"
            )
    else:
        lines.append("**This Device:** First time seen")

    if similar_devices:
        lines.append("\n**Similar Devices (same VID:PID):**")
        for dev in similar_devices[-3:]:  # Last 3 similar
            lines.append(
                f"  - {dev.get('timestamp', 'Unknown')}: "
                f"verdict={dev.get('verdict', 'Unknown')}, "
                f"risk_score={dev.get('risk_score', 'Unknown')}"
            )

    return "\n".join(lines)
