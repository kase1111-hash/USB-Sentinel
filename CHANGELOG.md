# Changelog

All notable changes to USB Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

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
