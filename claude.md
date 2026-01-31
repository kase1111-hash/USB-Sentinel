# Claude.md - USB-Sentinel

## Project Overview

USB-Sentinel is an LLM-integrated USB firewall that operates as a constitutional security layer between the operating system and USB subsystem. It combines deterministic rule-based policy enforcement with LLM-assisted heuristic analysis to detect and prevent USB-based attacks (BadUSB, Rubber Ducky, firmware exploits, class spoofing, data exfiltration).

**Status**: Alpha (v0.1.0) | **License**: MIT | **Python**: 3.10+

## Quick Start

```bash
# Setup development environment
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=sentinel

# Run linting
ruff check src/ && ruff format --check src/

# Type checking
mypy src/sentinel

# Start daemon (requires root/CAP_SYS_RAWIO)
sudo usb-sentinel start

# Dashboard (separate terminal)
cd dashboard && npm install && npm run dev
```

## Architecture

5-layer architecture with data flow: USB Event → Policy Engine → LLM Analyzer → Audit DB → Dashboard

| Layer | Location | Purpose |
|-------|----------|---------|
| L1 Interceptor | `src/sentinel/interceptor/` | USB event capture via pyudev/libusb before driver binding |
| L2 Policy Engine | `src/sentinel/policy/` | YAML-based deterministic allow/block/review rules |
| L3 LLM Analyzer | `src/sentinel/analyzer/` | Claude API heuristic threat assessment |
| L4 Virtual Proxy | `src/sentinel/proxy/` | USB/IP sandboxed device inspection |
| L5 Audit/API | `src/sentinel/audit/`, `api/` | SQLite logging, FastAPI REST, React dashboard |

## Key Files

| File | Purpose |
|------|---------|
| `src/sentinel/daemon.py` | Main orchestrator (`SentinelDaemon` class) |
| `src/sentinel/core/processor.py` | Integrated device evaluation pipeline |
| `src/sentinel/policy/engine.py` | Policy rule evaluation (`PolicyEngine`, `RuleMatcher`) |
| `src/sentinel/analyzer/llm.py` | Claude API integration (`LLMAnalyzer`) |
| `src/sentinel/audit/database.py` | SQLite operations (`AuditDatabase`) |
| `src/sentinel/api/routes.py` | FastAPI endpoints |
| `src/sentinel/interceptor/descriptors.py` | USB descriptor parsing (`DeviceDescriptor`) |
| `config/sentinel.yaml` | Daemon configuration |
| `config/policy.yaml` | Default security policy rules |

## Build & Test Commands

```bash
# Full test suite with coverage
pytest tests/ -v --cov=sentinel --cov-report=html

# Single test file
pytest tests/test_policy.py -v

# Async tests use pytest-asyncio (auto mode)
pytest tests/test_api.py -v

# Lint and format
ruff check src/ tests/
ruff format src/ tests/

# Type check (strict mode)
mypy src/sentinel

# Build package
python -m build
```

## Code Conventions

### Python Style
- **Type hints required** on all functions (MyPy enforces `disallow_untyped_defs`)
- **Line length**: 100 characters
- **Imports**: Use `from __future__ import annotations`, organize by stdlib/third-party/local
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes/enums
- **Dataclasses**: Preferred for data structures
- **Enums**: Use for categorical values (Action, EventType, TrustLevel, Verdict)

### File Template
```python
"""Module docstring."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.policy.models import PolicyRule

logger = logging.getLogger(__name__)
```

### Testing Patterns
- Fixtures in `tests/conftest.py` (temp dirs, sample devices, mock configs)
- Mock external APIs (Anthropic, USB hardware)
- Use `pytest.mark.asyncio` for async tests (auto mode enabled)

## Common Development Tasks

### Adding a Policy Rule
Edit `config/policy.yaml`:
```yaml
rules:
  - name: block_suspicious_hid
    match:
      class: 0x03  # HID
      endpoints: { min: 5 }  # Too many endpoints
    action: block
    comment: "Block HID devices with excessive endpoints"
```

### Extending LLM Analyzer
1. Add new analysis method to `src/sentinel/analyzer/llm.py`
2. Update prompts in `src/sentinel/analyzer/prompts.py`
3. Add tests in `tests/test_analyzer.py` with mocked API responses

### Adding an API Endpoint
1. Add route to `src/sentinel/api/routes.py`
2. Define schemas in `src/sentinel/api/schemas.py`
3. Add tests in `tests/test_api.py` using `httpx.AsyncClient`

### Modifying the Dashboard
1. Components in `dashboard/src/components/`
2. API client in `dashboard/src/api.ts`
3. WebSocket hook in `dashboard/src/hooks/useWebSocket.tsx`
4. Run `npm run dev` for hot reload

## Important Notes

### Platform Requirements
- **Linux only** for USB interception (pyudev/libusb)
- Requires **root privileges** or `CAP_SYS_RAWIO` capability
- udev rules in `scripts/99-usb-sentinel.rules`

### Database Design
- **Append-only**: SQLite triggers prevent deletion/modification of events
- Tables: `devices` (fingerprinted), `events` (audit log)
- WAL mode enabled for concurrent reads

### LLM Integration
- Primary: Anthropic Claude API (requires `ANTHROPIC_API_KEY`)
- Optional: Local llama.cpp (`pip install usb-sentinel[local-llm]`)
- Rate limited via token bucket algorithm
- Prompt injection protection in prompts.py

### Security Model
- **Zero-trust enumeration**: Devices blocked until explicitly allowed
- Default action configurable (block/review)
- mTLS authentication available for API
- Input sanitization before LLM analysis

## Configuration Reference

### sentinel.yaml
```yaml
daemon:
  log_level: INFO
  pid_file: /var/run/sentinel.pid

policy:
  rules_file: /etc/sentinel/policy.yaml
  default_action: review
  hot_reload: true

analyzer:
  provider: anthropic  # or "local"
  model: claude-sonnet-4-20250514
  rate_limit: 10  # requests/minute

api:
  host: 127.0.0.1
  port: 8080
  auth_mode: api_key  # none, api_key, mtls
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci.yaml`):
1. **Lint**: Ruff format/check
2. **Test**: pytest on Python 3.10, 3.11, 3.12 with coverage
3. **Type-check**: MyPy (non-blocking)
4. **Build**: Package verification

## Project Structure

```
USB-Sentinel/
├── src/sentinel/           # Main Python package
│   ├── interceptor/        # L1: USB event capture
│   ├── policy/             # L2: Rule engine
│   ├── analyzer/           # L3: LLM analysis
│   ├── proxy/              # L4: USB/IP sandbox
│   ├── audit/              # L5: Database
│   ├── api/                # REST API
│   ├── core/               # Processing pipeline
│   ├── cli.py              # CLI entry point
│   └── daemon.py           # Daemon orchestrator
├── dashboard/              # React frontend
├── config/                 # YAML configurations
├── tests/                  # pytest test suite
├── scripts/                # Installation scripts
└── docs: README.md, Spec.md, GUIDE.md
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied on USB | Run with sudo or set CAP_SYS_RAWIO |
| LLM rate limited | Adjust `analyzer.rate_limit` in config |
| Tests fail on macOS/Windows | USB interception is Linux-only; mock tests should pass |
| Database locked | Check for stale PID file, ensure single daemon instance |
