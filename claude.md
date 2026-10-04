# Claude.md - USB-Sentinel

## Project Overview

USB-Sentinel is a Linux USB firewall daemon. New USB devices stay unbound
(kernel `authorized_default=0`) until the daemon decides on them from YAML
policy rules, a descriptor validator, local heuristics, and optionally the
Claude API. Decisions are enforced through sysfs `authorized` flags and logged
to an append-only SQLite audit database. Targets BadUSB-style attacks
(keystroke injectors, HID+storage combos, vendor spoofing, known attack
hardware).

**Status**: Alpha (v0.1.0) | **License**: MIT | **Python**: 3.10+

## Quick Start

```bash
# Setup development environment
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Run tests (no USB hardware or API key needed)
pytest tests/

# Lint and format (CI fails on either)
ruff check src/ tests/ && ruff format --check src/ tests/

# Type checking (non-blocking in CI)
mypy src/sentinel --ignore-missing-imports

# Preview decisions for attached devices, then run the daemon (root)
sudo usb-sentinel scan
sudo sentinel-daemon -c config/sentinel.yaml
```

## Architecture

Data flow: udev event → sysfs descriptors → decision → sysfs `authorized` → audit DB

| Layer | Location | Purpose |
|-------|----------|---------|
| L1 Interceptor | `src/sentinel/interceptor/` | pyudev monitor; descriptors read from sysfs; enforcement via `authorized` / `authorized_default` |
| L2 Policy Engine | `src/sentinel/policy/` | YAML rules, first match wins: allow / block / review |
| L3 Analyzer | `src/sentinel/analyzer/`, `interceptor/validator.py` | Descriptor validator + local heuristics, optional Claude scoring |
| L4 Audit/API | `src/sentinel/audit/`, `api/` | SQLite audit log, optional FastAPI REST + WebSocket for `dashboard/` |

The decision pipeline lives in `SentinelDaemon.evaluate()` (`daemon.py`; the
module docstring describes the order). Key invariants:

- Operator trust (`devices trust`) overrides policy.
- The LLM score is combined with `max()`. Device strings reach the prompt, so
  the LLM may raise risk but never lower it below the local checks.
- Scores 51-75 hold the device unauthorized (trust level `review`); only the
  operator releases it.
- The policy parser rejects unknown keys and empty matches: a dropped key
  would widen a rule to every device.

## Key Files

| File | Purpose |
|------|---------|
| `src/sentinel/daemon.py` | `SentinelDaemon`: lifecycle, event handling, decision pipeline |
| `src/sentinel/interceptor/sysfs.py` | Descriptor parsing from sysfs, `DefaultDenyGuard` |
| `src/sentinel/interceptor/linux.py` | `USBMonitor` (pyudev via event loop), `USBInterceptor` |
| `src/sentinel/interceptor/validator.py` | Descriptor anomaly checks and scores |
| `src/sentinel/policy/parser.py` | Strict policy YAML parser |
| `src/sentinel/policy/engine.py` | Rule evaluation (`PolicyEngine`, `RuleMatcher`) |
| `src/sentinel/analyzer/llm.py` | Claude API (`LLMAnalyzer`), local heuristics (`MockLLMAnalyzer`) |
| `src/sentinel/analyzer/prompts.py` | Prompts, input sanitization, response validation |
| `src/sentinel/audit/database.py` | SQLite operations (`AuditDatabase`) |
| `src/sentinel/cli.py` | `usb-sentinel` commands |
| `src/sentinel/core/processor.py` | Standalone `DeviceProcessor` library (not used by the daemon) |
| `config/sentinel.yaml` | Daemon configuration (commented) |
| `config/policy.yaml` | Default policy; header lists every match key |
| `scripts/install.sh`, `scripts/usb-sentinel.service` | venv install, systemd unit |

## Build & Test Commands

```bash
# Full test suite with coverage (what CI runs)
pytest tests/ -v --cov=sentinel --cov-report=xml

# Detection benchmark with per-device table
pytest tests/benchmark -s -k report

# Lint and format
ruff check src/ tests/
ruff format src/ tests/

# Build package
python -m build
```

## Code Conventions

### Python Style
- **Type hints** on all functions
- **Line length**: 100 characters
- **Imports**: `from __future__ import annotations`, stdlib / third-party / local
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes/enums
- **Logging**: %-style arguments, not f-strings
- **Dataclasses** for data structures, **Enums** for categorical values

### Testing Patterns
- Fixtures in `tests/conftest.py`; daemon tests use a real temp SQLite DB and a
  `MagicMock` interceptor
- `tests/test_sysfs.py` builds a fake `/sys/bus/usb/devices` tree with real
  descriptor bytes; reuse `make_device()` for anything touching sysfs
- Mock the Anthropic client with typed content blocks
  (`SimpleNamespace(type="text", text=...)`), not bare `MagicMock`s
- Async tests run in pytest-asyncio auto mode

## Common Development Tasks

### Adding a Policy Rule
Edit `config/policy.yaml`, then `usb-sentinel policy validate`:
```yaml
rules:
  - match:
      class: HID
      endpoint_count_gt: 4
    action: block
    comment: "HID device with excessive endpoints"
```

### Adding a Match Key
1. Field on `MatchCondition` (`policy/models.py`)
2. Check in `RuleMatcher.matches()` (`policy/engine.py`)
3. Parse and validate in `parse_match_condition()` and add to `MATCH_KEYS`
   (`policy/parser.py`), and to `MatchConditionSchema` (`api/schemas.py`)
4. Document it in the `config/policy.yaml` header

### Extending the Analyzer
1. Local signals: `interceptor/validator.py` or `MockLLMAnalyzer` (`analyzer/llm.py`)
2. LLM prompt: `analyzer/prompts.py`; device strings go through `sanitize_input()`
3. Check the effect on `tests/benchmark` (it runs the real pipeline)

### Adding an API Endpoint
1. Route in `src/sentinel/api/routes.py`, schemas in `api/schemas.py`
2. Tests in `tests/test_api.py`

## Important Notes

### Platform Requirements
- **Linux only**; needs root to write `/sys/bus/usb/devices/*/authorized`
- The systemd unit must not set `ProtectKernelTunables` (makes `/sys` read-only)

### Database Design
- **Append-only**: SQLite triggers reject UPDATE/DELETE on `events`
- Tables: `devices` (fingerprint, trust level), `events` (audit log)

### LLM Integration
- Anthropic Claude API, enabled when `ANTHROPIC_API_KEY` is set; without it the
  daemon runs on local scoring
- Bounded by `interceptor.analysis_timeout`; client errors and refusals are not
  retried
- Optional local llama.cpp (`analyzer.provider: local`, `pip install usb-sentinel[local-llm]`)

## Configuration Reference

See the comments in `config/sentinel.yaml`. Notable settings:

```yaml
daemon:
  pid_file: /run/usb-sentinel/sentinel.pid
policy:
  rules_file: /etc/usb-sentinel/policy.yaml
  hot_reload: true
analyzer:
  model: claude-sonnet-5-5
  effort: low            # omit for models without effort support
interceptor:
  block_during_analysis: true   # authorized_default=0 while running
  analysis_timeout: 10
api:
  enabled: false
  auth_mode: api_key     # none, api_key
```

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci.yaml`):
1. **Lint**: ruff check + ruff format --check
2. **Test**: pytest on Python 3.10, 3.11, 3.12 with coverage
3. **Type-check**: mypy (non-blocking)
4. **Build**: package build (needs lint + test)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Could not set authorized_default" | Not root, or no USB buses in `/sys/bus/usb/devices` |
| A device is held | `usb-sentinel devices list --trust review`, then `devices trust <fp> trusted` |
| Policy change ignored | `usb-sentinel policy validate`; invalid policies are rejected and the old one kept |
| "Another usb-sentinel daemon is running" | Only one instance may run; check `usb-sentinel status` |
