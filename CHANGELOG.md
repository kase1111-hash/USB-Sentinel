# Changelog

All notable changes to USB Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New devices stay unbound (`authorized_default=0`) until the daemon decides;
  buses added later (docks) are covered too, and the previous setting is
  restored on shutdown
- Descriptors are read from sysfs, so unauthorized devices can be evaluated
  without libusb and without talking to the device
- Devices held for review (risk 51-75) stay unauthorized until an operator
  runs `usb-sentinel devices trust`, which now also applies immediately to an
  attached device
- `usb-sentinel scan` previews decisions for attached devices
- Policy reload on SIGHUP and on file change (`policy.hot_reload`), keeping the
  previous policy if the new one is invalid; `usb-sentinel policy reload`
- Webhook alerts for blocked and held devices
- Benchmark that runs the daemon's real decision path with the shipped policy

### Changed
- Reviews are always scored by the descriptor validator and local heuristics;
  the LLM is optional and can only raise a score
- An `allow` rule is re-examined when the vendor string contradicts the VID
- The policy parser rejects unknown keys, empty matches, unquoted numeric IDs
  and invalid regexes; `manufacturer: null` means "no manufacturer string"
- Default model is `claude-sonnet-5-5` (`claude-sonnet-4-20250514` is
  deprecated); optional `analyzer.effort`
- Installer uses a virtualenv; the udev RUN hook was removed
- A missing `ANTHROPIC_API_KEY` is a warning, not a startup error

### Fixed
- The shipped policy's `manufacturer: null` rule matched every device, making
  all later rules unreachable; keys the parser did not know were dropped,
  widening rules to every device
- 19 of 25 benchmark attack devices were authorized with the shipped config
- The daemon exited on the first device removal or bind event
- `devices trust` had no effect on decisions; `first_seen` rules always matched
- The udev hook authorized every device when it could not reach the daemon
- The systemd unit made `/sys` read-only, so no verdict could be enforced;
  SIGHUP (ExecReload) killed the daemon; the PID file was never written
- Device strings reached the LLM prompt unsanitized; responses that start with
  a thinking block failed to parse
- Audit log append-only triggers were never created
- `PUT /api/policy` called a method that did not exist
- `usb-sentinel policy test` crashed
- Validator false positives on webcams (IAD class, zero-bandwidth alternate
  settings) and on generic product names from verified vendors

## [0.1.0] - 2026-01-23

### Added

#### Core Infrastructure
- Project foundation with Python 3.10+ support
- Command-line interface (`usb-sentinel`) for device management
- Background daemon service (`sentinel-daemon`) with systemd integration
- Configuration system with YAML-based settings

#### USB Event Interception (Phase 2-3)
- Linux USB event interception using pyudev and libusb
- USB descriptor parsing for device identification
- Device fingerprinting based on VID/PID, class, and descriptors
- Real-time event capture before driver binding

#### Audit System (Phase 4)
- SQLite-based append-only audit database
- Forensic-grade event logging with full descriptor dumps
- Query interface for historical analysis

#### Policy Engine (Phase 5-6)
- YAML-based policy configuration
- Rule matching by VID/PID, device class, and attributes
- Three-tier verdict system: ALLOW, BLOCK, REVIEW
- Wildcard and pattern matching support

#### LLM Analyzer (Phase 7)
- Claude API integration for threat analysis
- Local LLM support via llama.cpp
- Risk scoring system (0-100 scale)
- Prompt injection protection
- Behavioral pattern analysis

#### Virtual USB Proxy (Phase 8)
- USB/IP protocol support for device proxying
- Sandboxed device inspection environment
- HID traffic simulation and capture
- Isolated namespace for safe testing

#### Dashboard Backend (Phase 9)
- FastAPI REST API with OpenAPI documentation
- WebSocket support for real-time updates
- mTLS and API key authentication
- Event streaming and device status endpoints

#### Dashboard Frontend (Phase 10)
- React 18 single-page application
- Real-time device monitoring
- Event timeline visualization
- Policy management interface
- Risk score charts with Recharts

#### DevOps
- GitHub Actions CI/CD pipeline
- Multi-version Python testing (3.10, 3.11, 3.12)
- Ruff linting and formatting
- MyPy type checking
- Pytest test suite with coverage reporting
- Automated installation script

### Security
- Zero-trust device enumeration model
- Defense-in-depth architecture with 5 security layers
- Input sanitization against prompt injection
- Append-only audit logs for tamper evidence
- Capability-restricted daemon process

[Unreleased]: https://github.com/kase1111-hash/USB-Sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kase1111-hash/USB-Sentinel/releases/tag/v0.1.0
