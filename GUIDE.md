# USB Sentinel Implementation Guide

A 10-phase development guide for building the LLM-integrated USB firewall system.

---

## Phase 1: Project Foundation & Environment Setup

**Goal**: Establish the project structure, development environment, and core dependencies.

### Tasks

1. **Initialize Python project with pyproject.toml**
   ```toml
   [project]
   name = "usb-sentinel"
   version = "0.1.0"
   requires-python = ">=3.10"
   dependencies = [
       "pyusb>=1.2.0",
       "pyyaml>=6.0",
       "anthropic>=0.20.0",
       "fastapi>=0.100.0",
       "uvicorn>=0.23.0",
       "sqlalchemy>=2.0.0",
       "websockets>=11.0"
   ]
   ```

2. **Create directory structure**
   ```
   usb-sentinel/
   ├── src/sentinel/
   │   ├── __init__.py
   │   ├── interceptor/
   │   ├── policy/
   │   ├── analyzer/
   │   ├── proxy/
   │   ├── audit/
   │   └── api/
   ├── dashboard/
   ├── config/
   ├── scripts/
   └── tests/
   ```

3. **Set up development tools**
   - Configure pytest for testing
   - Set up ruff/black for linting
   - Create virtual environment

4. **Create base configuration files**
   - `config/sentinel.yaml` - Daemon configuration
   - `config/policy.yaml` - Default policy rules

### Deliverables
- [ ] Working Python package with importable modules
- [ ] Development environment with all dependencies
- [ ] Base configuration templates
- [ ] CI/CD pipeline configuration (GitHub Actions)

### Key Files
```
src/sentinel/__init__.py
src/sentinel/config.py          # Configuration loader
pyproject.toml
config/sentinel.yaml
```

---

## Phase 2: USB Event Interceptor (Linux)

**Goal**: Capture USB device insertion events before OS driver binding.

### Tasks

1. **Implement libusb/PyUSB device enumeration**
   ```python
   # src/sentinel/interceptor/linux.py
   import usb.core
   import usb.util

   def enumerate_devices():
       """List all currently connected USB devices."""
       return list(usb.core.find(find_all=True))

   def get_device_by_path(bus: int, address: int):
       """Find specific device by bus/address."""
       return usb.core.find(bus=bus, address=address)
   ```

2. **Create udev rule for device interception**
   ```bash
   # scripts/99-usb-sentinel.rules
   ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", \
       RUN+="/opt/usb-sentinel/bin/intercept %k %p"
   ```

3. **Implement device event listener daemon**
   - Monitor `/dev` for USB device changes
   - Use pyudev for event-driven detection
   - Queue events for processing

4. **Build blocking mechanism**
   - Prevent driver binding until analysis complete
   - Use `authorized` attribute in sysfs
   - Implement timeout for safety

### Deliverables
- [ ] USB device enumeration working
- [ ] udev integration capturing new devices
- [ ] Ability to block/allow device binding
- [ ] Event queue for async processing

### Key Files
```
src/sentinel/interceptor/__init__.py
src/sentinel/interceptor/linux.py
src/sentinel/interceptor/events.py
scripts/99-usb-sentinel.rules
```

---

## Phase 3: Descriptor Parsing & Device Fingerprinting

**Goal**: Extract and parse USB descriptors, generate unique device fingerprints.

### Tasks

1. **Implement descriptor extraction**
   ```python
   # src/sentinel/interceptor/descriptors.py
   from dataclasses import dataclass
   from typing import Optional

   @dataclass
   class DeviceDescriptor:
       vid: str                    # Vendor ID (hex)
       pid: str                    # Product ID (hex)
       device_class: int
       device_subclass: int
       device_protocol: int
       manufacturer: Optional[str]
       product: Optional[str]
       serial: Optional[str]
       interfaces: list['InterfaceDescriptor']

   @dataclass
   class InterfaceDescriptor:
       interface_class: int
       interface_subclass: int
       interface_protocol: int
       num_endpoints: int
       endpoints: list['EndpointDescriptor']
   ```

2. **Parse all descriptor levels**
   - Device descriptor
   - Configuration descriptor
   - Interface descriptors
   - Endpoint descriptors
   - String descriptors

3. **Implement device fingerprinting**
   ```python
   # src/sentinel/policy/fingerprint.py
   import hashlib

   def generate_fingerprint(descriptor: DeviceDescriptor) -> str:
       """Generate stable fingerprint for device identification."""
       components = [
           descriptor.vid,
           descriptor.pid,
           str(descriptor.device_class),
           descriptor.manufacturer or "",
           descriptor.product or "",
           # Include interface classes for composite devices
           ",".join(str(i.interface_class) for i in descriptor.interfaces)
       ]
       data = "|".join(components).encode()
       return hashlib.sha256(data).hexdigest()[:16]
   ```

4. **Build descriptor validation**
   - Validate class/subclass combinations
   - Check endpoint consistency
   - Detect anomalous configurations

### Deliverables
- [ ] Complete descriptor parsing for all USB descriptor types
- [ ] Stable fingerprint generation
- [ ] Descriptor validation with anomaly detection
- [ ] JSON serialization for logging/analysis

### Key Files
```
src/sentinel/interceptor/descriptors.py
src/sentinel/policy/fingerprint.py
src/sentinel/interceptor/validator.py
```

---

## Phase 4: Audit Database & Logging

**Goal**: Implement persistent storage for devices, events, and forensic data.

### Tasks

1. **Design SQLite schema**
   ```sql
   -- Devices table
   CREATE TABLE devices (
       id INTEGER PRIMARY KEY,
       fingerprint TEXT UNIQUE NOT NULL,
       vid TEXT NOT NULL,
       pid TEXT NOT NULL,
       manufacturer TEXT,
       product TEXT,
       serial TEXT,
       first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       last_seen TIMESTAMP,
       trust_level TEXT DEFAULT 'unknown'
   );

   -- Events table (append-only)
   CREATE TABLE events (
       id INTEGER PRIMARY KEY,
       timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       device_fingerprint TEXT NOT NULL,
       event_type TEXT NOT NULL,
       policy_rule TEXT,
       llm_analysis TEXT,
       risk_score INTEGER,
       verdict TEXT,
       raw_descriptor BLOB,
       FOREIGN KEY (device_fingerprint) REFERENCES devices(fingerprint)
   );

   -- Append-only trigger
   CREATE TRIGGER no_delete_events
   BEFORE DELETE ON events
   BEGIN
       SELECT RAISE(ABORT, 'Deletion not permitted on audit log');
   END;
   ```

2. **Implement database operations**
   ```python
   # src/sentinel/audit/database.py
   from sqlalchemy import create_engine
   from sqlalchemy.orm import sessionmaker

   class AuditDatabase:
       def __init__(self, path: str):
           self.engine = create_engine(f"sqlite:///{path}")
           self.Session = sessionmaker(bind=self.engine)

       def log_event(self, event: Event) -> int:
           """Log event and return event ID."""
           pass

       def get_device(self, fingerprint: str) -> Optional[Device]:
           """Retrieve device by fingerprint."""
           pass

       def update_trust_level(self, fingerprint: str, level: str):
           """Update device trust level."""
           pass
   ```

3. **Create data models**
   - SQLAlchemy ORM models
   - Pydantic schemas for validation
   - JSON export format

4. **Implement audit log integrity**
   - Append-only enforcement
   - Optional hash chain for tamper detection
   - Log rotation without deletion

### Deliverables
- [ ] SQLite database with full schema
- [ ] CRUD operations for devices and events
- [ ] Append-only audit log enforcement
- [ ] Export functionality for forensics

### Key Files
```
src/sentinel/audit/__init__.py
src/sentinel/audit/database.py
src/sentinel/audit/models.py
src/sentinel/audit/schema.sql
```

---

## Phase 5: Policy Engine Core

**Goal**: Build the YAML policy parser and rule data structures.

### Tasks

1. **Define policy rule schema**
   ```python
   # src/sentinel/policy/models.py
   from dataclasses import dataclass
   from typing import Optional, Union
   from enum import Enum

   class Action(Enum):
       ALLOW = "allow"
       BLOCK = "block"
       REVIEW = "review"

   @dataclass
   class MatchCondition:
       vid: Optional[str] = None
       pid: Optional[str] = None
       device_class: Optional[Union[str, int]] = None
       manufacturer: Optional[str] = None  # regex
       product: Optional[str] = None       # regex
       serial: Optional[str] = None        # regex
       has_storage_endpoint: Optional[bool] = None
       has_hid_endpoint: Optional[bool] = None
       endpoint_count_gt: Optional[int] = None
       first_seen: Optional[bool] = None

   @dataclass
   class PolicyRule:
       match: MatchCondition
       action: Action
       comment: str = ""
       priority: int = 0
   ```

2. **Implement YAML policy parser**
   ```python
   # src/sentinel/policy/parser.py
   import yaml
   from pathlib import Path

   def load_policy(path: Path) -> list[PolicyRule]:
       """Load and validate policy from YAML file."""
       with open(path) as f:
           data = yaml.safe_load(f)

       rules = []
       for rule_data in data.get('rules', []):
           rule = parse_rule(rule_data)
           validate_rule(rule)
           rules.append(rule)
       return rules
   ```

3. **Build policy validation**
   - Schema validation
   - Rule conflict detection
   - Syntax checking for regex patterns

4. **Create default policy template**
   ```yaml
   # config/policy.yaml
   rules:
     # Trusted devices whitelist
     - match:
         vid: '046d'
         pid: 'c534'
       action: allow
       comment: 'Logitech Unifying Receiver'

     # Block known attack hardware
     - match:
         vid: '1a86'
         pid: '7523'
       action: block
       comment: 'CH340 - common in attack hardware'

     # Review suspicious patterns
     - match:
         class: 'HID'
         has_storage_endpoint: true
       action: review
       comment: 'HID with storage - suspicious'

     # Default: review everything unknown
     - match: '*'
       action: review
   ```

### Deliverables
- [ ] Policy rule data structures
- [ ] YAML parser with validation
- [ ] Default policy template
- [ ] Policy syntax documentation

### Key Files
```
src/sentinel/policy/__init__.py
src/sentinel/policy/models.py
src/sentinel/policy/parser.py
config/policy.yaml
```

---

## Phase 6: Policy Matching & Evaluation Engine

**Goal**: Implement rule matching logic and verdict determination.

### Tasks

1. **Build rule matching engine**
   ```python
   # src/sentinel/policy/engine.py
   import re
   from typing import Optional

   class PolicyEngine:
       def __init__(self, rules: list[PolicyRule]):
           self.rules = rules

       def evaluate(self, device: DeviceDescriptor,
                    db: AuditDatabase) -> tuple[Action, Optional[PolicyRule]]:
           """Evaluate device against policy rules."""
           for rule in self.rules:
               if self._matches(rule.match, device, db):
                   return rule.action, rule
           return Action.REVIEW, None

       def _matches(self, condition: MatchCondition,
                    device: DeviceDescriptor,
                    db: AuditDatabase) -> bool:
           """Check if device matches condition."""
           if condition.vid and condition.vid != device.vid:
               return False
           if condition.pid and condition.pid != device.pid:
               return False
           # ... additional condition checks
           return True
   ```

2. **Implement condition matchers**
   - Exact match (VID/PID)
   - Regex match (manufacturer, product, serial)
   - Boolean checks (has_storage_endpoint, first_seen)
   - Numeric comparisons (endpoint_count_gt)

3. **Add first-seen detection**
   ```python
   def is_first_seen(self, fingerprint: str, db: AuditDatabase) -> bool:
       """Check if device has been seen before."""
       return db.get_device(fingerprint) is None
   ```

4. **Implement endpoint analysis helpers**
   ```python
   def has_storage_endpoint(device: DeviceDescriptor) -> bool:
       """Check if device has mass storage capability."""
       MASS_STORAGE_CLASS = 0x08
       return any(
           intf.interface_class == MASS_STORAGE_CLASS
           for intf in device.interfaces
       )

   def has_hid_endpoint(device: DeviceDescriptor) -> bool:
       """Check if device has HID capability."""
       HID_CLASS = 0x03
       return any(
           intf.interface_class == HID_CLASS
           for intf in device.interfaces
       )
   ```

5. **Build evaluation pipeline**
   - Rule ordering (top-to-bottom)
   - First-match-wins semantics
   - Logging of matched rules

### Deliverables
- [ ] Complete rule matching for all condition types
- [ ] First-seen detection integrated with database
- [ ] Policy evaluation returns verdict + matched rule
- [ ] Comprehensive test coverage

### Key Files
```
src/sentinel/policy/engine.py
src/sentinel/policy/matchers.py
tests/test_policy.py
```

---

## Phase 7: LLM Analyzer Integration

**Goal**: Integrate Claude API for heuristic threat analysis.

### Tasks

1. **Create LLM client wrapper**
   ```python
   # src/sentinel/analyzer/llm.py
   import anthropic
   import json
   from typing import Optional

   class LLMAnalyzer:
       def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
           self.client = anthropic.Anthropic(api_key=api_key)
           self.model = model

       def analyze(self, device: DeviceDescriptor,
                   history: Optional[list] = None) -> AnalysisResult:
           """Analyze device using LLM."""
           prompt = self._build_prompt(device, history)
           response = self.client.messages.create(
               model=self.model,
               max_tokens=1024,
               system=SYSTEM_PROMPT,
               messages=[{"role": "user", "content": prompt}]
           )
           return self._parse_response(response)
   ```

2. **Design analysis prompts**
   ```python
   # src/sentinel/analyzer/prompts.py
   SYSTEM_PROMPT = '''You are a USB security analyst agent. Evaluate USB device
   descriptors for potential security threats.

   Constitutional bounds:
   1. You MUST provide risk_score (0-100) and verdict (ALLOW/BLOCK/SANDBOX)
   2. You MUST explain reasoning in the analysis field
   3. You CANNOT recommend actions outside USB device handling
   4. You MUST flag uncertainty rather than guess

   Output JSON only: {"risk_score": int, "verdict": str, "analysis": str}'''
   ```

3. **Implement risk scoring**
   ```python
   # src/sentinel/analyzer/scoring.py
   @dataclass
   class AnalysisResult:
       risk_score: int          # 0-100
       verdict: str             # ALLOW/BLOCK/SANDBOX
       analysis: str            # Explanation
       confidence: float        # 0-1

   def score_to_action(score: int) -> Action:
       """Convert risk score to action."""
       if score <= 25:
           return Action.ALLOW
       elif score <= 50:
           return Action.ALLOW  # monitored
       elif score <= 75:
           return Action.SANDBOX
       else:
           return Action.BLOCK
   ```

4. **Add response validation**
   - JSON schema validation
   - Sanitize against prompt injection
   - Handle malformed responses

5. **Implement local LLM fallback**
   ```python
   # Optional: llama.cpp integration for offline use
   class LocalLLMAnalyzer:
       def __init__(self, model_path: str):
           # Initialize llama.cpp
           pass
   ```

6. **Build async analysis queue**
   - Rate limiting (token bucket)
   - Retry with exponential backoff
   - Timeout handling

### Deliverables
- [ ] Claude API integration working
- [ ] Risk scoring system implemented
- [ ] Input sanitization for prompt injection
- [ ] Response validation and parsing
- [ ] Optional local LLM fallback

### Key Files
```
src/sentinel/analyzer/__init__.py
src/sentinel/analyzer/llm.py
src/sentinel/analyzer/prompts.py
src/sentinel/analyzer/scoring.py
src/sentinel/analyzer/local.py
```

---

## Phase 8: Virtual USB Proxy Layer

**Goal**: Implement sandboxed device inspection via USB/IP.

### Tasks

1. **USB/IP wrapper implementation**
   ```python
   # src/sentinel/proxy/usbip.py
   import subprocess
   from dataclasses import dataclass

   @dataclass
   class ProxyDevice:
       bus_id: str
       local_port: int
       status: str

   class USBIPProxy:
       def bind_device(self, bus_id: str) -> bool:
           """Bind device to usbip for export."""
           result = subprocess.run(
               ["usbip", "bind", "-b", bus_id],
               capture_output=True
           )
           return result.returncode == 0

       def attach_device(self, host: str, bus_id: str) -> bool:
           """Attach remote device via usbip."""
           result = subprocess.run(
               ["usbip", "attach", "-r", host, "-b", bus_id],
               capture_output=True
           )
           return result.returncode == 0
   ```

2. **Implement traffic capture**
   ```python
   # src/sentinel/proxy/capture.py
   class USBTrafficCapture:
       def __init__(self, device_path: str):
           self.device_path = device_path
           self.packets = []

       def start_capture(self):
           """Start capturing USB traffic via usbmon."""
           pass

       def stop_capture(self) -> list[USBPacket]:
           """Stop capture and return packets."""
           pass
   ```

3. **Build HID behavior analyzer**
   ```python
   # src/sentinel/proxy/hid.py
   @dataclass
   class KeystrokeAnalysis:
       avg_interval_ms: float
       min_interval_ms: float
       modifier_sequences: list[str]
       decoded_text: str
       is_suspicious: bool

   def analyze_hid_traffic(packets: list[USBPacket]) -> KeystrokeAnalysis:
       """Analyze HID traffic for suspicious patterns."""
       keystrokes = extract_keystrokes(packets)

       # Detect superhuman typing (< 10ms between keys)
       intervals = calculate_intervals(keystrokes)
       is_suspicious = min(intervals) < 10

       # Detect dangerous modifier sequences
       modifiers = detect_modifier_patterns(keystrokes)

       return KeystrokeAnalysis(
           avg_interval_ms=sum(intervals) / len(intervals),
           min_interval_ms=min(intervals),
           modifier_sequences=modifiers,
           decoded_text=decode_keystrokes(keystrokes),
           is_suspicious=is_suspicious
       )
   ```

4. **Implement sandbox behaviors**
   - Keystroke throttling (buffer rapid input)
   - Modifier sequence blocking
   - Re-enumeration detection

5. **Traffic replay for analysis**
   ```python
   def replay_traffic(capture_file: str, analyzer: LLMAnalyzer):
       """Replay captured traffic for LLM analysis."""
       packets = load_capture(capture_file)
       analysis = analyze_hid_traffic(packets)
       return analyzer.analyze_behavior(analysis)
   ```

### Deliverables
- [ ] USB/IP integration for device proxying
- [ ] Traffic capture via usbmon
- [ ] HID keystroke analysis
- [ ] Sandbox throttling and blocking
- [ ] Traffic replay functionality

### Key Files
```
src/sentinel/proxy/__init__.py
src/sentinel/proxy/usbip.py
src/sentinel/proxy/capture.py
src/sentinel/proxy/hid.py
src/sentinel/proxy/sandbox.py
```

---

## Phase 9: Dashboard Backend API

**Goal**: Build FastAPI backend for dashboard and external integrations.

### Tasks

1. **Set up FastAPI application**
   ```python
   # src/sentinel/api/__init__.py
   from fastapi import FastAPI
   from fastapi.middleware.cors import CORSMiddleware

   app = FastAPI(
       title="USB Sentinel API",
       version="1.0.0"
   )

   app.add_middleware(
       CORSMiddleware,
       allow_origins=["http://localhost:3000"],
       allow_methods=["*"],
       allow_headers=["*"]
   )
   ```

2. **Implement REST endpoints**
   ```python
   # src/sentinel/api/routes.py
   from fastapi import APIRouter, HTTPException

   router = APIRouter(prefix="/api")

   @router.get("/devices")
   async def list_devices(trust_level: str = None):
       """List all known devices."""
       pass

   @router.get("/devices/{fingerprint}")
   async def get_device(fingerprint: str):
       """Get device details and history."""
       pass

   @router.put("/devices/{fingerprint}/trust")
   async def update_trust(fingerprint: str, level: str):
       """Update device trust level."""
       pass

   @router.get("/events")
   async def list_events(
       device: str = None,
       event_type: str = None,
       since: datetime = None
   ):
       """Query event log."""
       pass

   @router.get("/policy")
   async def get_policy():
       """Get current policy rules."""
       pass

   @router.put("/policy")
   async def update_policy(rules: list[PolicyRule]):
       """Update policy rules."""
       pass

   @router.post("/analyze")
   async def manual_analyze(device_info: dict):
       """Manually trigger LLM analysis."""
       pass
   ```

3. **Implement WebSocket for real-time events**
   ```python
   # src/sentinel/api/websocket.py
   from fastapi import WebSocket
   from typing import Set

   class EventBroadcaster:
       def __init__(self):
           self.connections: Set[WebSocket] = set()

       async def connect(self, websocket: WebSocket):
           await websocket.accept()
           self.connections.add(websocket)

       async def broadcast(self, event: dict):
           for connection in self.connections:
               await connection.send_json(event)

   @app.websocket("/api/events/stream")
   async def event_stream(websocket: WebSocket):
       await broadcaster.connect(websocket)
       try:
           while True:
               await websocket.receive_text()
       except WebSocketDisconnect:
           broadcaster.connections.remove(websocket)
   ```

4. **Add authentication (mTLS)**
   - Certificate-based authentication
   - API key fallback for development
   - Rate limiting

5. **Build Pydantic schemas**
   ```python
   # src/sentinel/api/schemas.py
   from pydantic import BaseModel
   from datetime import datetime

   class DeviceResponse(BaseModel):
       fingerprint: str
       vid: str
       pid: str
       manufacturer: str | None
       product: str | None
       trust_level: str
       first_seen: datetime
       last_seen: datetime

   class EventResponse(BaseModel):
       id: int
       timestamp: datetime
       device_fingerprint: str
       event_type: str
       verdict: str | None
       risk_score: int | None
   ```

### Deliverables
- [ ] All REST endpoints implemented
- [ ] WebSocket real-time event stream
- [ ] Pydantic request/response schemas
- [ ] Authentication middleware
- [ ] OpenAPI documentation

### Key Files
```
src/sentinel/api/__init__.py
src/sentinel/api/routes.py
src/sentinel/api/websocket.py
src/sentinel/api/schemas.py
src/sentinel/api/auth.py
```

---

## Phase 10: Dashboard Frontend & System Integration

**Goal**: Build React dashboard and integrate all components.

### Tasks

1. **Initialize React application**
   ```bash
   cd dashboard
   npm create vite@latest . -- --template react-ts
   npm install @tanstack/react-query axios recharts tailwindcss
   ```

2. **Build core dashboard components**
   ```jsx
   // dashboard/src/components/DeviceList.tsx
   export function DeviceList() {
     const { data: devices } = useQuery(['devices'], fetchDevices);

     return (
       <div className="device-list">
         {devices?.map(device => (
           <DeviceCard
             key={device.fingerprint}
             device={device}
           />
         ))}
       </div>
     );
   }

   // dashboard/src/components/EventFeed.tsx
   export function EventFeed() {
     const [events, setEvents] = useState([]);

     useEffect(() => {
       const ws = new WebSocket('ws://localhost:8000/api/events/stream');
       ws.onmessage = (e) => {
           setEvents(prev => [JSON.parse(e.data), ...prev]);
       };
       return () => ws.close();
     }, []);

     return (
       <div className="event-feed">
         {events.map(event => (
           <EventRow key={event.id} event={event} />
         ))}
       </div>
     );
   }
   ```

3. **Implement dashboard views**
   - **Dashboard Home**: Real-time device feed, recent events, risk overview
   - **Device Inventory**: All known devices with trust management
   - **Event Log**: Searchable event history with filters
   - **Policy Editor**: YAML editor with validation
   - **Analysis Reports**: LLM analysis results with export

4. **Build policy editor**
   ```jsx
   // dashboard/src/components/PolicyEditor.tsx
   export function PolicyEditor() {
     const [yaml, setYaml] = useState('');
     const [errors, setErrors] = useState([]);

     const validatePolicy = async () => {
       const result = await api.validatePolicy(yaml);
       setErrors(result.errors);
     };

     return (
       <div className="policy-editor">
         <CodeEditor
           value={yaml}
           onChange={setYaml}
           language="yaml"
         />
         <ValidationErrors errors={errors} />
         <button onClick={validatePolicy}>Validate</button>
       </div>
     );
   }
   ```

5. **System integration**
   - Create main daemon entry point
   - Integrate all layers (interceptor → policy → analyzer → audit)
   - Build CLI interface

   ```python
   # src/sentinel/daemon.py
   class SentinelDaemon:
       def __init__(self, config_path: str):
           self.config = load_config(config_path)
           self.interceptor = USBInterceptor()
           self.policy = PolicyEngine(load_policy(self.config.policy_path))
           self.analyzer = LLMAnalyzer(self.config.api_key)
           self.db = AuditDatabase(self.config.db_path)
           self.api = create_api(self.db, self.policy)

       async def run(self):
           """Main daemon loop."""
           async for event in self.interceptor.events():
               await self.handle_device(event)

       async def handle_device(self, event: DeviceEvent):
           """Process device through all layers."""
           descriptor = event.descriptor
           fingerprint = generate_fingerprint(descriptor)

           # Layer 2: Policy evaluation
           action, rule = self.policy.evaluate(descriptor, self.db)

           # Layer 3: LLM analysis if needed
           if action == Action.REVIEW:
               result = await self.analyzer.analyze(descriptor)
               action = score_to_action(result.risk_score)

           # Execute verdict
           self.execute_verdict(event, action)

           # Log event
           self.db.log_event(Event(
               device_fingerprint=fingerprint,
               event_type='connect',
               verdict=action.value
           ))
   ```

6. **Create installation script**
   ```bash
   # scripts/install.sh
   #!/bin/bash
   set -e

   # Install Python package
   pip install -e .

   # Install udev rules
   sudo cp scripts/99-usb-sentinel.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules

   # Create config directory
   sudo mkdir -p /etc/usb-sentinel
   sudo cp config/*.yaml /etc/usb-sentinel/

   # Create systemd service
   sudo cp scripts/usb-sentinel.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable usb-sentinel

   echo "USB Sentinel installed successfully"
   ```

7. **Documentation and testing**
   - Write user documentation
   - Integration tests
   - Performance benchmarks

### Deliverables
- [ ] Complete React dashboard
- [ ] Integrated daemon with all layers
- [ ] CLI interface
- [ ] Installation scripts
- [ ] systemd service configuration
- [ ] User documentation
- [ ] Integration test suite

### Key Files
```
dashboard/src/App.tsx
dashboard/src/components/
src/sentinel/daemon.py
src/sentinel/cli.py
scripts/install.sh
scripts/usb-sentinel.service
docs/user-guide.md
```

---

## Summary

| Phase | Focus Area | Key Deliverable |
|-------|------------|-----------------|
| 1 | Foundation | Project structure and dependencies |
| 2 | Interceptor | USB event capture via udev |
| 3 | Descriptors | Parsing and fingerprinting |
| 4 | Audit | SQLite database and logging |
| 5 | Policy Core | YAML parser and rule structures |
| 6 | Policy Engine | Rule matching and evaluation |
| 7 | LLM | Claude API integration |
| 8 | Proxy | USB/IP sandbox layer |
| 9 | API | FastAPI backend |
| 10 | Dashboard | React frontend and integration |

## Testing Strategy

Each phase should include:
- Unit tests for new components
- Integration tests with previous phases
- Mock devices for testing without hardware

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=sentinel --cov-report=html
```

## Security Checklist

Before release, verify:
- [ ] Daemon runs with minimal privileges
- [ ] Policy files are root-owned with restricted permissions
- [ ] LLM input sanitization prevents prompt injection
- [ ] Audit log is append-only
- [ ] API requires authentication
- [ ] No default credentials anywhere
