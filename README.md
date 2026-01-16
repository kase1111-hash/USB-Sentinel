# USB Sentinel

LLM-Integrated USB Firewall System

A constitutional security layer that interposes between the operating system and physical USB subsystem. USB Sentinel combines deterministic rule-based policy enforcement with LLM-assisted heuristic analysis to detect and prevent USB-based attack vectors including BadUSB, Rubber Ducky scripts, and firmware-level exploits.

## Overview

USB Sentinel operates on the principle of **zero-trust device enumeration**: no USB device gains system access until it passes both static policy checks and behavioral analysis. The LLM component functions as a specialized security analyst agent, evaluating device descriptors against known attack patterns and historical baselines.

## Features

- Intercept all USB device enumeration events before OS-level driver binding
- Enforce configurable policies based on VID/PID, device class, and descriptor attributes
- Analyze device behavior patterns using LLM-powered threat classification
- Real-time audit logging with forensic-grade detail
- Sandboxed device testing via virtual USB layer

## Threat Model

USB Sentinel addresses the following attack categories:

| Attack Vector | Description | Detection Method |
|---------------|-------------|------------------|
| BadUSB / Rubber Ducky | HID devices injecting keystrokes or commands | Behavioral timing analysis, keystroke pattern detection |
| Class Spoofing | Device claiming multiple incompatible classes | Descriptor consistency validation |
| Firmware Manipulation | Modified firmware with malicious payloads | Vendor string anomaly detection, signature verification |
| Data Exfiltration | Storage devices with hidden partitions | Endpoint enumeration analysis |
| Power Surge Attacks | USB killers and overcurrent devices | Power draw monitoring (hardware-assisted) |

## Architecture

USB Sentinel employs a five-layer architecture following the principle of defense-in-depth:

| Layer | Component | Technology | Function |
|-------|-----------|------------|----------|
| L1 | Event Interceptor | libusb / usbmon / udev | Capture raw USB events before driver binding |
| L2 | Policy Engine | Python + YAML rules | Deterministic allow/block based on device attributes |
| L3 | LLM Analyzer | Claude API / local llama.cpp | Heuristic threat assessment and anomaly detection |
| L4 | Virtual USB Proxy | usbip / VHCI | Sandboxed device inspection and traffic replay |
| L5 | Audit & Dashboard | SQLite + FastAPI + React | Logging, visualization, and incident response |

### Data Flow

1. Kernel notifies udev of device insertion event
2. Event Interceptor captures device descriptor before driver loads
3. Policy Engine evaluates against static rules (fast path)
4. If policy result is REVIEW, LLM Analyzer performs deep inspection
5. Final decision (ALLOW/BLOCK/SANDBOX) returned to Policy Engine
6. udev rule executes corresponding action (bind driver or reject)
7. Event logged to audit database with full descriptor dump

## Policy Configuration

Policies are defined in YAML format:

```yaml
rules:
  # Whitelist known trusted devices by VID:PID
  - match:
      vid: '046d'
      pid: 'c534'
    action: allow
    comment: 'Logitech Unifying Receiver'

  # Block known malicious devices
  - match:
      vid: '1a86'
      pid: '7523'
    action: block
    comment: 'CH340 - common in attack hardware'

  # Review any HID device with storage endpoints
  - match:
      class: 'HID'
      has_storage_endpoint: true
    action: review
    comment: 'Suspicious class combination'

  # Default: review unknown devices
  - match: '*'
    action: review
```

## LLM Risk Scoring

| Score Range | Verdict | Action Taken |
|-------------|---------|--------------|
| 0-25 | ALLOW | Device permitted; logged as low-risk |
| 26-50 | ALLOW (MONITORED) | Device permitted with enhanced logging |
| 51-75 | SANDBOX | Device routed through virtual USB layer |
| 76-100 | BLOCK | Device rejected; alert generated |

## Repository Structure

```
usb-sentinel/
├── src/
│   └── sentinel/
│       ├── interceptor/     # USB event capture (Linux/Windows)
│       ├── policy/          # Rule evaluation and YAML parsing
│       ├── analyzer/        # LLM integration and risk scoring
│       ├── proxy/           # USB/IP and traffic capture
│       ├── audit/           # SQLite logging and data models
│       └── api/             # FastAPI endpoints and WebSocket
├── dashboard/               # React frontend
├── config/                  # Policy and daemon configuration
├── scripts/                 # Installation and udev rules
└── tests/                   # Test suite and fixtures
```

## Security Considerations

- **Daemon Security**: Runs with minimal privileges using capability-restricted process namespace
- **Policy Protection**: Root-owned config files with integrity monitoring
- **LLM Security**: Input sanitization against prompt injection; output validation against expected schema
- **Audit Integrity**: Append-only database with optional remote logging
- **Dashboard Auth**: mTLS for API; no default credentials

## License

MIT License
