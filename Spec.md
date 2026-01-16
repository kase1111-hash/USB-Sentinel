USB SENTINEL
LLM-Integrated USB Firewall System

Technical Specification Document
Version 1.0

Classification: Open Source / MIT License
January 2026

1. Executive Summary
USB Sentinel is a constitutional security layer that interposes between the operating system and physical USB subsystem. It combines deterministic rule-based policy enforcement with LLM-assisted heuristic analysis to detect and prevent USB-based attack vectors including BadUSB, Rubber Ducky scripts, and firmware-level exploits.
The system operates on the principle of zero-trust device enumeration: no USB device gains system access until it passes both static policy checks and behavioral analysis. The LLM component functions as a specialized security analyst agent, evaluating device descriptors against known attack patterns and historical baselines.
1.1 Core Objectives
⦁	Intercept all USB device enumeration events before OS-level driver binding
⦁	Enforce configurable policies based on VID/PID, device class, and descriptor attributes
⦁	Analyze device behavior patterns using LLM-powered threat classification
⦁	Provide real-time audit logging with forensic-grade detail
⦁	Support sandboxed device testing via virtual USB layer
1.2 Threat Model
USB Sentinel addresses the following attack categories:
Attack Vector	Description	Detection Method
BadUSB / Rubber Ducky	HID devices injecting keystrokes or commands	Behavioral timing analysis, keystroke pattern detection
Class Spoofing	Device claiming multiple incompatible classes	Descriptor consistency validation
Firmware Manipulation	Modified firmware with malicious payloads	Vendor string anomaly detection, signature verification
Data Exfiltration	Storage devices with hidden partitions	Endpoint enumeration analysis
Power Surge Attacks	USB killers and overcurrent devices	Power draw monitoring (hardware-assisted)

2. System Architecture
USB Sentinel employs a five-layer architecture, each with distinct responsibilities and constitutional bounds. The design follows the principle of defense-in-depth, where each layer can independently block malicious devices.
2.1 Architecture Overview
Layer	Component	Technology	Function
L1	Event Interceptor	libusb / usbmon / udev	Capture raw USB events before driver binding
L2	Policy Engine	Python + YAML rules	Deterministic allow/block based on device attributes
L3	LLM Analyzer	Claude API / local llama.cpp	Heuristic threat assessment and anomaly detection
L4	Virtual USB Proxy	usbip / VHCI	Sandboxed device inspection and traffic replay
L5	Audit & Dashboard	SQLite + FastAPI + React	Logging, visualization, and incident response
2.2 Data Flow
When a USB device connects, the following sequence executes:
1.	Kernel notifies udev of device insertion event
2.	Event Interceptor captures device descriptor before driver loads
3.	Policy Engine evaluates against static rules (fast path)
4.	If policy result is REVIEW, LLM Analyzer performs deep inspection
5.	Final decision (ALLOW/BLOCK/SANDBOX) returned to Policy Engine
6.	udev rule executes corresponding action (bind driver or reject)
7.	Event logged to audit database with full descriptor dump
2.3 Constitutional Bounds
Following Agent-OS principles, each component operates within explicit constitutional constraints:
Component	Constitutional Bound	Enforcement
Event Interceptor	Read-only access to USB subsystem; cannot modify descriptors	Capability-restricted process namespace
Policy Engine	Cannot access network; decisions based only on local rules	Seccomp sandbox with blocked syscalls
LLM Analyzer	Rate-limited API calls; no persistent state between analyses	Token bucket + ephemeral context
Virtual USB Proxy	Isolated network namespace; no host filesystem access	Container with dropped capabilities
Audit System	Append-only database; no delete operations permitted	SQLite triggers + filesystem ACL

3. Layer 1: USB Event Interceptor
The Event Interceptor serves as the lowest-level component, capturing USB device enumeration events and descriptor data before the operating system binds drivers.
3.1 Implementation Options
3.1.1 Linux: udev + libusb
Primary approach for Linux systems. A udev rule triggers on device insertion, invoking the interceptor daemon which reads descriptors via libusb before allowing driver binding.
# /etc/udev/rules.d/99-usb-sentinel.rules
ACTION=="add", SUBSYSTEM=="usb", RUN+="/opt/usb-sentinel/intercept.py %k"
3.1.2 Linux: usbmon (Kernel Module)
For traffic-level inspection, usbmon provides raw packet capture. Useful for behavioral analysis post-enumeration.
# Mount debugfs and read from usbmon
mount -t debugfs none /sys/kernel/debug
cat /sys/kernel/debug/usb/usbmon/0u
3.1.3 Windows: WinUSB + DeviceIoControl
Windows implementation requires a filter driver or WinUSB-based interception. The SetupAPI provides device notification callbacks.
3.2 Descriptor Extraction
The interceptor extracts the following descriptor fields for policy evaluation:
Field	Source	Security Relevance
idVendor (VID)	Device Descriptor	Identifies manufacturer; spoofable
idProduct (PID)	Device Descriptor	Identifies product model; spoofable
bDeviceClass	Device Descriptor	High-level device category
bInterfaceClass	Interface Descriptor	Specific functionality (HID, Storage, etc.)
iManufacturer	String Descriptor	Human-readable vendor name; anomaly detection
iProduct	String Descriptor	Product name; pattern matching for known attacks
iSerialNumber	String Descriptor	Unique identifier; fingerprinting
bNumEndpoints	Interface Descriptor	Endpoint count; class consistency validation
bmAttributes	Config Descriptor	Power attributes; self-powered vs bus-powered
3.3 Python Reference Implementation
import usb.core
import usb.util
import json
from datetime import datetime

def extract_device_info(dev):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "vid": hex(dev.idVendor),
        "pid": hex(dev.idProduct),
        "device_class": dev.bDeviceClass,
        "manufacturer": usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else None,
        "product": usb.util.get_string(dev, dev.iProduct) if dev.iProduct else None,
        "serial": usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else None,
        "interfaces": [extract_interface(intf) for cfg in dev for intf in cfg]
    }

4. Layer 2: Policy Engine
The Policy Engine implements deterministic, rule-based device authorization. It evaluates device attributes against a configured ruleset and returns one of three verdicts: ALLOW, BLOCK, or REVIEW (escalate to LLM Analyzer).
4.1 Policy Language
Policies are defined in YAML format, inspired by usbguard but extended with LLM escalation triggers:
# /etc/usb-sentinel/policy.yaml

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

  # Review devices with empty manufacturer strings
  - match:
      manufacturer: null
    action: review
    comment: 'Missing vendor identification'

  # Default: review unknown devices
  - match: '*'
    action: review
4.2 Rule Evaluation Order
Rules are evaluated top-to-bottom. First matching rule determines the action. This allows specific whitelists to override generic reviews:
1.	Explicit ALLOW rules (trusted device whitelist)
2.	Explicit BLOCK rules (known malicious signatures)
3.	Anomaly-triggered REVIEW rules (suspicious patterns)
4.	Default REVIEW catchall (zero-trust baseline)
4.3 Supported Match Conditions
Condition	Type	Description
vid	string (hex)	Vendor ID exact match
pid	string (hex)	Product ID exact match
vid_range	string[]	Vendor ID in range
class	string/int	Device or interface class
manufacturer	regex	Manufacturer string pattern
product	regex	Product string pattern
serial	regex	Serial number pattern
has_storage_endpoint	bool	Device has mass storage capability
has_hid_endpoint	bool	Device has HID capability
endpoint_count_gt	int	More than N endpoints
first_seen	bool	Device never seen before

5. Layer 3: LLM Analyzer
The LLM Analyzer provides heuristic threat assessment for devices that pass static policy checks but warrant deeper inspection. It operates as a specialized security analyst agent with constitutional bounds preventing overreach.
5.1 Analysis Capabilities
5.1.1 Descriptor Anomaly Detection
The LLM evaluates descriptor consistency against device class specifications:
⦁	A keyboard (HID class 0x03) should not have mass storage endpoints
⦁	Endpoint counts should match declared interface capabilities
⦁	String descriptors should match vendor conventions
5.1.2 Historical Fingerprint Comparison
Each device generates a fingerprint hash based on descriptor attributes. The LLM compares new devices against:
⦁	User's historical device database (legitimate devices seen before)
⦁	Known attack device signatures (Rubber Ducky, BadUSB patterns)
⦁	Manufacturer baseline profiles (expected descriptors for VID)
5.1.3 Behavioral Pattern Analysis
For HID devices, the analyzer can evaluate keystroke timing and patterns:
⦁	Superhuman typing speeds indicate scripted injection
⦁	Rapid modifier key sequences (ALT+F2, WIN+R) suggest command injection
⦁	Repeated enumeration cycles may indicate firmware probing
5.2 API Integration
The analyzer supports multiple LLM backends with a unified interface:
# analyzer.py
import anthropic
import json

SYSTEM_PROMPT = '''You are a USB security analyst agent. Your role is to evaluate
USB device descriptors for potential security threats. You operate under these
constitutional bounds:

1. You MUST provide a risk_score (0-100) and verdict (ALLOW/BLOCK/SANDBOX)
2. You MUST explain your reasoning in the analysis field
3. You CANNOT recommend actions outside USB device handling
4. You MUST flag uncertainty rather than guess

Output JSON only: {"risk_score": int, "verdict": str, "analysis": str}'''

def analyze_device(device_info: dict, client: anthropic.Anthropic) -> dict:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Analyze this USB device:\n{json.dumps(device_info, indent=2)}"
        }]
    )
    return json.loads(response.content[0].text)
5.3 Risk Scoring Matrix
Score Range	Verdict	Action Taken
0-25	ALLOW	Device permitted; logged as low-risk
26-50	ALLOW (MONITORED)	Device permitted with enhanced logging
51-75	SANDBOX	Device routed through virtual USB layer
76-100	BLOCK	Device rejected; alert generated
5.4 Example Analysis Output
{
  "risk_score": 85,
  "verdict": "BLOCK",
  "analysis": "Device claims HID class (keyboard) but declares 3 endpoints
    including bulk transfer capability typical of mass storage. Manufacturer
    string 'USB Device' is generic placeholder commonly seen in attack
    hardware. Pattern consistent with Rubber Ducky or similar HID injection
    tool. Recommend blocking and alerting user."
}

6. Layer 4: Virtual USB Proxy
The Virtual USB Proxy provides deep inspection capability by routing device traffic through a controlled sandbox. This allows behavioral analysis without exposing the host system to potential attacks.
6.1 Implementation Architecture
Two primary approaches are supported:
6.1.1 USB/IP (Network-Based)
USB/IP allows USB devices to be shared over TCP/IP. The proxy acts as a man-in-the-middle:
1.	Physical device attaches to proxy host (isolated VM or container)
2.	Proxy exports device via usbip daemon
3.	Main host imports device via usbip client with traffic logging
4.	All USB packets captured for analysis before forwarding
# On proxy host (isolated environment)
usbip bind -b 1-1.2
usbipd

# On main host
usbip attach -r proxy-host -b 1-1.2
6.1.2 VHCI (Virtual Host Controller)
VHCI creates a virtual USB host controller, allowing complete control over device presentation to the OS. This enables traffic modification and injection for testing.
6.2 Sandbox Behaviors
Behavior	Detection Method	Sandbox Response
Rapid keystroke injection	Timing analysis (<10ms between keys)	Buffer and throttle to human speed
Modifier key sequences	Pattern matching (WIN+R, ALT+F2)	Alert and optionally block
Mass storage access	Endpoint traffic monitoring	Log all file operations
Re-enumeration cycling	Device disconnect/reconnect count	Block after threshold
6.3 Traffic Replay for Analysis
Captured USB traffic can be replayed to the LLM Analyzer for post-hoc behavioral analysis:
def replay_hid_traffic(capture_file: str, analyzer) -> dict:
    """Replay captured HID traffic and analyze keystroke patterns."""
    packets = parse_usbmon_capture(capture_file)
    keystrokes = extract_hid_reports(packets)
    
    timing_analysis = {
        "avg_interval_ms": calculate_avg_interval(keystrokes),
        "min_interval_ms": min(k.interval for k in keystrokes),
        "modifier_sequences": detect_modifier_patterns(keystrokes),
        "decoded_text": decode_keystrokes(keystrokes)
    }
    
    return analyzer.analyze_hid_behavior(timing_analysis)

7. Layer 5: Audit System & Dashboard
The Audit System provides comprehensive logging, forensic data retention, and real-time visualization of USB security events.
7.1 Database Schema
SQLite database with append-only event logging:
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT UNIQUE NOT NULL,
    vid TEXT NOT NULL,
    pid TEXT NOT NULL,
    manufacturer TEXT,
    product TEXT,
    serial TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    trust_level TEXT DEFAULT 'unknown'
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    device_fingerprint TEXT NOT NULL,
    event_type TEXT NOT NULL,  -- 'connect', 'disconnect', 'blocked', 'allowed'
    policy_rule TEXT,
    llm_analysis TEXT,
    risk_score INTEGER,
    verdict TEXT,
    raw_descriptor BLOB,
    FOREIGN KEY (device_fingerprint) REFERENCES devices(fingerprint)
);

-- Append-only enforcement
CREATE TRIGGER no_delete_events BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'Deletion not permitted on audit log');
END;
7.2 Dashboard API
FastAPI-based REST interface for dashboard and external integrations:
Endpoint	Method	Description
/api/devices	GET	List all known devices with trust levels
/api/devices/{fingerprint}	GET	Get device details and event history
/api/devices/{fingerprint}/trust	PUT	Update device trust level (whitelist/blacklist)
/api/events	GET	Query event log with filters
/api/events/stream	WebSocket	Real-time event stream
/api/policy	GET/PUT	View or update policy rules
/api/analyze	POST	Manual device analysis via LLM
7.3 Dashboard Features
⦁	Real-time device connection feed with risk indicators
⦁	Device inventory with trust level management
⦁	Timeline visualization of connection events
⦁	Policy rule editor with validation
⦁	LLM analysis reports with exportable forensic data
⦁	Alert configuration for high-risk events

8. Development Roadmap
8.1 Phase 1: Foundation (Weeks 1-2)
Establish core USB event capture and logging infrastructure.
Deliverable	Priority	Effort
USB event listener (libusb/PyUSB)	Critical	3 days
Descriptor extraction and parsing	Critical	2 days
SQLite audit database	Critical	1 day
Basic CLI for device listing	High	1 day
udev rule integration (Linux)	High	2 days
8.2 Phase 2: Policy Engine (Weeks 3-4)
Implement rule-based policy evaluation.
Deliverable	Priority	Effort
YAML policy parser	Critical	2 days
Rule matching engine	Critical	3 days
Device fingerprinting	High	2 days
Whitelist/blacklist management	High	1 day
Policy validation and testing	Medium	2 days
8.3 Phase 3: LLM Integration (Weeks 5-6)
Add AI-powered threat analysis.
Deliverable	Priority	Effort
Claude API integration	Critical	2 days
Analysis prompt engineering	Critical	3 days
Risk scoring system	High	2 days
Local LLM fallback (llama.cpp)	Medium	2 days
Async analysis queue	Medium	1 day
8.4 Phase 4: Virtual USB Layer (Weeks 7-8)
Implement sandboxed device inspection.
Deliverable	Priority	Effort
USB/IP proxy setup	High	3 days
Traffic capture and logging	High	2 days
HID behavior analysis	Medium	3 days
Traffic replay system	Medium	2 days
8.5 Phase 5: Dashboard (Weeks 9-10)
Build visualization and management interface.
Deliverable	Priority	Effort
FastAPI backend	Critical	2 days
React dashboard UI	Critical	4 days
WebSocket real-time feed	High	1 day
Policy editor	Medium	2 days
Export and reporting	Medium	1 day

9. Repository Structure
usb-sentinel/
├── README.md
├── LICENSE
├── pyproject.toml
├── src/
│   ├── sentinel/
│   │   ├── __init__.py
│   │   ├── interceptor/
│   │   │   ├── __init__.py
│   │   │   ├── linux.py          # udev + libusb implementation
│   │   │   ├── windows.py        # WinUSB implementation
│   │   │   └── descriptors.py    # Descriptor parsing
│   │   ├── policy/
│   │   │   ├── __init__.py
│   │   │   ├── engine.py         # Rule evaluation
│   │   │   ├── parser.py         # YAML policy parser
│   │   │   └── fingerprint.py    # Device fingerprinting
│   │   ├── analyzer/
│   │   │   ├── __init__.py
│   │   │   ├── llm.py            # Claude/LLM integration
│   │   │   ├── prompts.py        # System prompts
│   │   │   └── scoring.py        # Risk calculation
│   │   ├── proxy/
│   │   │   ├── __init__.py
│   │   │   ├── usbip.py          # USB/IP wrapper
│   │   │   └── capture.py        # Traffic capture
│   │   ├── audit/
│   │   │   ├── __init__.py
│   │   │   ├── database.py       # SQLite operations
│   │   │   └── models.py         # Data models
│   │   └── api/
│   │       ├── __init__.py
│   │       ├── routes.py         # FastAPI endpoints
│   │       └── websocket.py      # Real-time events
├── dashboard/
│   ├── package.json
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   └── hooks/
├── config/
│   ├── policy.yaml              # Default policy
│   └── sentinel.yaml            # Daemon config
├── scripts/
│   ├── install.sh
│   └── 99-usb-sentinel.rules    # udev rules
└── tests/
    ├── test_interceptor.py
    ├── test_policy.py
    └── fixtures/                # Sample descriptors

10. Security Considerations
10.1 Threat Surface
USB Sentinel itself introduces attack surface that must be hardened:
Risk	Mitigation
Daemon compromise gives USB control	Run with minimal privileges; capability-restricted
Policy file tampering	Root-owned config; integrity monitoring
LLM prompt injection via descriptors	Input sanitization; output validation
Audit log tampering	Append-only database; optional remote logging
Dashboard authentication bypass	mTLS for API; no default credentials
10.2 LLM Security
The LLM Analyzer presents unique security considerations:
⦁	Device descriptors may contain adversarial strings attempting prompt injection
⦁	LLM responses must be validated against expected JSON schema before acting
⦁	Rate limiting prevents resource exhaustion from rapid device insertion
⦁	Local LLM fallback ensures operation when network unavailable
10.3 Operational Security
⦁	Default-deny policy recommended for high-security environments
⦁	Separate audit log retention from operational database
⦁	Consider hardware USB firewall for air-gapped systems
⦁	Regular policy review and device inventory audits

Appendix A: USB Class Codes Reference
Code	Class	Security Notes
0x00	Defined at Interface	Check interface descriptors
0x01	Audio	Generally low risk
0x02	Communications (CDC)	May have multiple interfaces
0x03	HID	HIGH RISK - keyboard/mouse injection
0x05	Physical	Specialized; rare
0x06	Image	Cameras; data exfil risk
0x07	Printer	Data exfil risk
0x08	Mass Storage	HIGH RISK - malware delivery
0x09	Hub	Physical layer; inspect children
0x0A	CDC-Data	Paired with CDC control
0x0B	Smart Card	Sensitive credentials
0x0E	Video	Webcams; privacy risk
0xE0	Wireless	Bluetooth/WiFi adapters
0xEF	Miscellaneous	Composite devices; inspect all
0xFE	Application Specific	Firmware update; HIGH RISK
0xFF	Vendor Specific	UNKNOWN RISK - requires analysis

Appendix B: Known Attack Device Signatures
Device	VID:PID	Indicators
USB Rubber Ducky	Various	HID class, 'ATMEL' or generic strings
Bash Bunny	Various	Multiple classes, rapid re-enum
WiFi Pineapple	0x0CF3:*	Atheros VID with unusual PIDs
LAN Turtle	0x0B95:*	ASIX VID; network adapter
USB Armory	0x0525:*	Gadget mode; multiple classes
P4wnP1	Raspberry Pi	Composite HID+Network+Storage

— End of Specification —
