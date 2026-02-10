# USB-Sentinel Refocus Plan

**Goal:** Get the core loop working end-to-end, prove the LLM value proposition, then rebuild outward.

**Current state:** The daemon crashes on the first USB device insertion. The REST API calls methods that don't exist. The proxy layer is dead code. The React dashboard has no functioning backend. Individual modules are well-written but never successfully integrated.

**Target state:** A CLI/daemon that intercepts a USB device, evaluates it against policy, optionally runs LLM analysis, logs the decision, and executes the verdict -- without crashing.

---

## Phase 0: Stop the Bleeding (Day 1)

**Objective:** Make the daemon not crash.

There are exactly 3 broken integration points. Fix them:

### Fix 1: daemon.py:241 -- `register_device()` does not exist

```
File:  src/sentinel/daemon.py:241
Calls: self.db.register_device(fingerprint, vid, pid, manufacturer, product, serial)
Fix:   Change to self.db.add_device(fingerprint, vid, pid, manufacturer, product, serial)
```

`add_device()` lives at `src/sentinel/audit/database.py:209` with compatible parameters. This is a rename, not a logic change.

### Fix 2: routes.py:501 -- `engine.last_modified` attribute missing

```
File:  src/sentinel/api/routes.py:501
Reads: engine.last_modified
Fix:   The code already uses hasattr() guard. Add a last_modified attr to PolicyEngine.__init__()
       initialized to datetime.now(timezone.utc), updated in reload_policy().
```

### Fix 3: routes.py:549 -- `engine.update_rules()` does not exist

```
File:  src/sentinel/api/routes.py:549
Calls: engine.update_rules(new_rules)
Fix:   Add update_rules() method to PolicyEngine that replaces self.policy.rules
       and rebuilds the internal RuleMatcher.
```

### Verification

After these 3 fixes, run:
```bash
pytest tests/ -v --tb=short
```

If tests pass, the daemon can at least process a device without `AttributeError`. This is the minimum bar.

---

## Phase 1: Cut Dead Code (Day 1-2)

**Objective:** Remove code that is not on the critical path and has zero imports from core modules.

### Remove the proxy layer entirely

```
DELETE: src/sentinel/proxy/capture.py    (696 LOC)
DELETE: src/sentinel/proxy/hid.py        (597 LOC)
DELETE: src/sentinel/proxy/sandbox.py    (627 LOC)
DELETE: src/sentinel/proxy/usbip.py      (622 LOC)
DELETE: src/sentinel/proxy/__init__.py   (94 LOC)
DELETE: tests/test_proxy.py              (701 LOC)
```

**Why safe:** Zero imports from any core module. Verified:
- `daemon.py` -- no proxy imports
- `cli.py` -- no proxy imports
- `core/processor.py` -- no proxy imports
- `analyzer/*` -- no proxy imports
- `policy/*` -- no proxy imports
- `audit/*` -- no proxy imports

The proxy was "Phase 8" in the roadmap but was never wired in. It's 5,337 lines of dead code.

### Remove notification script

```
DELETE: scripts/usb-sentinel-notify  (98 LOC)
```

Desktop notifications are a distraction. The daemon should log decisions, not pop up toasts.

### Clean up references

After deletion, grep for any remaining imports or references to `sentinel.proxy` and remove them. Check `pyproject.toml` for any proxy-related entry points.

**Total removed: ~5,435 LOC. Zero functional impact.**

---

## Phase 2: Decouple the Dashboard and API (Day 2-3)

**Objective:** Make the daemon work without the API/WebSocket/dashboard. Don't delete them -- just make them optional.

### Make WebSocket conditional in daemon.py

The daemon currently hard-imports:
```python
from sentinel.api.websocket import (
    WebSocketEventType,
    broadcast_device_event,
    init_websocket,
    shutdown_websocket,
)
```

Wrap in a conditional:
```python
# In __init__:
self._api_enabled = config.get("api", {}).get("enabled", False)

# In start():
if self._api_enabled:
    from sentinel.api.websocket import init_websocket
    await init_websocket()

# In handle_device_event():
if self._api_enabled:
    from sentinel.api.websocket import broadcast_device_event, WebSocketEventType
    await broadcast_device_event(...)

# In stop():
if self._api_enabled:
    from sentinel.api.websocket import shutdown_websocket
    await shutdown_websocket()
```

### Make API startup conditional in daemon.py

The daemon starts uvicorn unconditionally. Gate it behind config:
```python
if self._api_enabled:
    await self._start_api_server()
```

### Update config/sentinel.yaml

Add a clear toggle:
```yaml
api:
  enabled: false  # Set to true to enable REST API + dashboard
```

Default to `false`. The daemon's job is to intercept and evaluate USB devices, not serve a web app.

### Don't touch the dashboard

Leave `dashboard/` as-is. It's a separate app with a separate build chain. It works when the API works. Just don't make it a dependency of core functionality.

**Result:** The daemon can run in pure CLI mode: intercept -> policy -> LLM -> audit -> log. No web server, no WebSocket, no React. The critical path is isolated.

---

## Phase 3: Fix the Python Time Bombs (Day 3)

**Objective:** Replace deprecated APIs before they break in Python 3.14.

### Replace `datetime.utcnow()` everywhere (15+ occurrences)

Files to change:
```
src/sentinel/policy/engine.py:379, 392, 413
src/sentinel/audit/database.py:259, 376, 463, 529, 566, 587
src/sentinel/audit/models.py:68, 69, 104
src/sentinel/interceptor/linux.py:46
src/sentinel/api/auth.py:53, 62, 475
src/sentinel/core/processor.py:62, 175, 205, 231
src/sentinel/interceptor/descriptors.py:207, 327
```

Replace with:
```python
from datetime import datetime, timezone
datetime.now(timezone.utc)
```

### Replace `asyncio.get_event_loop()`

```
src/sentinel/analyzer/llm.py:354
```

Replace with:
```python
asyncio.get_running_loop()
```

### Remove mTLS stub

```
src/sentinel/api/auth.py:479-500
```

`extract_client_cert()` returns `None` unconditionally. Delete it. It's dead code pretending to be a feature.

### Fix trust_level placeholder

```
src/sentinel/policy/engine.py:240-245
```

Currently:
```python
device_trust = "unknown"  # Placeholder - always "unknown"
```

Wire it to the actual database:
```python
device_trust = self.fingerprint_db.get(fingerprint, {}).get("trust_level", "unknown")
```

Or if that's too complex for now, add a `# TODO: wire to database` comment and remove the condition from policy matching so it doesn't silently swallow rules.

---

## Phase 4: Write the Integration Tests That Should Have Existed (Day 3-5)

**Objective:** Write tests that exercise the actual integration between layers, not mocked boundaries.

The current test suite has 424 tests but **zero** test the full flow `daemon -> policy -> analyzer -> database`. Every test mocks at least one intermediate layer, which is exactly why the `register_device()` bug was never caught.

### Create `tests/test_daemon_integration.py`

```python
"""Integration tests for the daemon's device processing pipeline.

These tests use REAL components (no mocking of internal layers) to verify
the full flow: event -> policy -> analyzer -> database -> verdict.
"""

class TestDaemonDeviceFlow:
    """Test SentinelDaemon.handle_device_event() with real components."""

    def test_known_device_allowed(self, real_db, real_policy_engine):
        """A whitelisted Logitech keyboard is allowed and logged."""
        # Uses real AuditDatabase, real PolicyEngine
        # Calls handle_device_event() with a Logitech descriptor
        # Asserts: device in DB, event logged, verdict=ALLOW

    def test_unknown_device_reviewed(self, real_db, real_policy_engine):
        """An unknown device triggers REVIEW and is logged."""
        # No LLM configured -> falls back to REVIEW
        # Asserts: device in DB, event logged, verdict=REVIEW

    def test_blacklisted_device_blocked(self, real_db, real_policy_engine):
        """A Rubber Ducky signature is blocked immediately."""
        # Asserts: device in DB, event logged, verdict=BLOCK

    def test_new_device_registered_in_database(self, real_db, real_policy_engine):
        """First-time device is persisted via add_device()."""
        # THIS IS THE TEST THAT CATCHES THE register_device() BUG
        # Asserts: db.get_device(fingerprint) is not None

    def test_repeat_device_not_re_registered(self, real_db, real_policy_engine):
        """Second insertion of same device skips registration."""
        # Asserts: add_device() called once, not twice
```

### Create `tests/test_routes_integration.py`

```python
"""Integration tests for API routes with real database."""

class TestRoutesWithRealDB:
    """Test API endpoints against a real SQLite database."""

    def test_list_devices_returns_daemon_created_devices(self, ...):
        """Devices created by the daemon are retrievable via API."""
        # Create device via db.add_device() (as daemon would)
        # GET /api/devices
        # Assert device appears in response

    def test_event_type_serialization_roundtrip(self, ...):
        """event_type survives daemon -> DB -> API -> response."""
        # Log event with event_type as daemon would
        # GET /api/events
        # Assert event_type field is correct
```

### Key principle

These tests must NOT mock `AuditDatabase`, `PolicyEngine`, or `LLMAnalyzer`. They should use real instances against a temp SQLite database. The only acceptable mocks are:
- USB hardware (no real device needed)
- Claude API (use `MockLLMAnalyzer` from `events.py`)
- System calls (`sysfs` writes)

### Update conftest.py

Add fixtures for real (non-mocked) components:
```python
@pytest.fixture
def real_db(tmp_path):
    """Real SQLite database in temp directory."""
    db = AuditDatabase(str(tmp_path / "test.db"))
    db.initialize()
    yield db
    db.close()

@pytest.fixture
def real_policy_engine(sample_policy, tmp_path):
    """Real policy engine with sample rules."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(sample_policy)
    return PolicyEngine(str(policy_path))
```

---

## Phase 5: Prove the LLM Value Proposition (Day 5-7)

**Objective:** Demonstrate that the LLM analyzer detects threats that static policy rules miss. If it doesn't, the project's differentiator is gone.

### Build a benchmark dataset

Create `tests/benchmark/` with two sets:

**Malicious descriptors (25+):**
- Rubber Ducky (HID-only, keystroke injection signature)
- BadUSB (mass storage claiming HID)
- Class spoofing (VID says keyboard, descriptors say network)
- Vendor string mismatch (claims "Logitech" but VID is Chinese generic)
- Multi-interface attack (HID + mass storage + network)
- Firmware DFU devices posing as input devices
- Devices with excessive endpoint counts
- Known attack tool signatures (CH340, STM32 DFU, Bash Bunny)

**Benign descriptors (25+):**
- Standard keyboards (Logitech, Microsoft, Apple)
- Standard mice
- USB flash drives (Kingston, SanDisk)
- Webcams
- Printers
- Bluetooth adapters
- USB hubs
- Audio devices

### Run the benchmark

```python
# tests/test_benchmark.py

def test_policy_only_detection_rate():
    """Policy engine alone: measure false positives and false negatives."""
    # Run all 50 descriptors through PolicyEngine only
    # Record: TP, FP, TN, FN
    # Expected: high FN rate (policy misses novel attacks)

def test_policy_plus_llm_detection_rate():
    """Policy + LLM: measure improvement over policy-only."""
    # Run REVIEW verdicts through LLM analyzer
    # Record: TP, FP, TN, FN
    # Expected: lower FN rate (LLM catches novel patterns)

def test_llm_adds_value():
    """Assert LLM meaningfully improves detection."""
    # Compare the two rates
    # If LLM doesn't improve detection by at least 20%, flag it
```

### What success looks like

- Policy-only catches obvious signatures (Rubber Ducky VID, known bad PIDs) but misses class spoofing, vendor mismatches, and novel attack patterns
- Policy + LLM catches 80%+ of the novel attacks that policy missed
- False positive rate stays below 10%

### What failure looks like

- LLM adds < 10% detection improvement over policy alone
- LLM has > 20% false positive rate
- LLM latency makes the system unusable (> 5s per device)

If the benchmark shows failure, the project needs to pivot: either improve the prompts/scoring, or accept that static rules are sufficient and drop the LLM layer.

---

## Phase 6: Harden for Real Use (Day 7-10)

**Objective:** Make the daemon reliable enough to run on a real workstation.

### Graceful degradation

- If Claude API is unreachable, fall back to local analyzer, not crash
- If database is locked, retry with backoff, not crash
- If policy file is malformed, keep last-good policy, not crash
- If udev monitor disconnects, reconnect, not crash

### Configuration validation

The config loader (`config.py:214-260`) skips validation for:
- USB class codes in `bypass_classes`
- URLs in `cors_origins` and `webhook`
- File path existence and writability

Add validation at startup. Fail fast with clear error messages.

### Logging

Replace f-string logging in hot paths with lazy %-formatting:
```python
# Before (allocates string even if DEBUG is disabled):
logger.info(f"Processing device: {vid}:{pid}")

# After:
logger.info("Processing device: %s:%s", vid, pid)
```

Affects: `routes.py:288, 550`, `auth.py:182, 570`, `daemon.py:232-233, 249, 258, 270-272, 275`

---

## What NOT To Do

- **Don't add Windows/macOS support.** Linux-only is fine. Portability is a distraction until the Linux version works.
- **Don't add more LLM providers.** Claude API + local fallback is sufficient. OpenAI/Gemini support adds complexity with no value until the core works.
- **Don't invest in the dashboard.** A beautiful UI for a broken backend is waste. CLI-first. Dashboard can come in v0.3.0.
- **Don't add policy templates.** The YAML policy format is fine. Ship with the current default policy and let users customize.
- **Don't optimize performance.** The system processes one USB device at a time. Optimization is premature until there's a working system to optimize.

---

## Success Criteria

The refocus is complete when:

1. `usb-sentinel daemon` starts without error
2. Inserting a USB device produces a log entry with the correct verdict
3. `usb-sentinel devices` lists seen devices from the audit database
4. `usb-sentinel events` shows the event history
5. `pytest tests/` passes with zero failures, including the new integration tests
6. The LLM benchmark shows measurable improvement over policy-only detection
7. The codebase has no `datetime.utcnow()` or `asyncio.get_event_loop()` calls

Everything else is v0.2.0.

---

## Timeline

| Phase | Days | Effort | Risk |
|-------|------|--------|------|
| 0: Stop the bleeding | 1 | 3 fixes, < 20 lines changed | None |
| 1: Cut dead code | 1 | Delete ~5,400 LOC | None (verified no deps) |
| 2: Decouple API/dashboard | 1-2 | Conditional imports, config flag | Low |
| 3: Fix Python deprecations | 1 | Find-and-replace, ~30 lines | None |
| 4: Integration tests | 2-3 | ~300-400 LOC of new tests | Medium (may find more bugs) |
| 5: LLM benchmark | 2-3 | ~50 descriptors + benchmark harness | High (may disprove value prop) |
| 6: Harden | 2-3 | Error handling, validation | Low |

**Total: 10-14 days to a working v0.1.0.**

Phase 5 is the highest-risk item. If the LLM doesn't demonstrably add value, the project needs a fundamental reassessment -- not more features.
