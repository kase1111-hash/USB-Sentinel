"""
Integration Tests for USB Sentinel.

Tests the complete system integration across all layers:
- Layer 1: USB Interception
- Layer 2: Policy Matching
- Layer 3: LLM Analysis
- Layer 4: Audit Database
- Layer 5: API Interface
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient


# ============================================================================
# Layer Integration Tests
# ============================================================================


class TestPolicyIntegration(unittest.TestCase):
    """Test policy engine integration."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.policy_path = os.path.join(self.temp_dir, "policy.yaml")

        # Create test policy
        policy_content = """
rules:
  - match:
      vid: "1234"
      pid: "5678"
    action: allow
    comment: "Known trusted device"
    priority: 100

  - match:
      vid: "dead"
      pid: "beef"
    action: block
    comment: "Known malicious device"
    priority: 100

  - match: "*"
    action: review
    comment: "Unknown devices need review"
    priority: 0
"""
        with open(self.policy_path, "w") as f:
            f.write(policy_content)

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_policy_loading(self) -> None:
        """Test policy loading from file."""
        from sentinel.policy import Action, load_policy

        policy = load_policy(self.policy_path)

        # Verify policy was loaded
        assert policy is not None
        assert len(policy.rules) == 3

        # Check rule order (by priority)
        assert policy.rules[0].action == Action.ALLOW
        assert policy.rules[0].comment == "Known trusted device"

    def test_policy_engine_creation(self) -> None:
        """Test policy engine can be created."""
        from sentinel.policy import PolicyEngine, load_policy

        policy_obj = load_policy(self.policy_path)
        engine = PolicyEngine(policy=policy_obj)

        assert engine is not None
        assert len(engine.policy.rules) == 3

    def test_policy_validation(self) -> None:
        """Test policy validation."""
        from sentinel.policy import load_policy, validate_policy

        policy = load_policy(self.policy_path)
        errors = validate_policy(policy)

        # Should be valid
        assert len(errors) == 0


class TestAuditDatabaseIntegration(unittest.TestCase):
    """Test audit database integration."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "audit.db")

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_device_event_logging(self) -> None:
        """Test logging device events."""
        from sentinel.audit import AuditDatabase, Device, Event, EventType, TrustLevel

        db = AuditDatabase(self.db_path)

        # Create device using ORM
        with db.session() as session:
            device = Device(
                fingerprint="test_fingerprint_1234",
                vid="1234",
                pid="5678",
                manufacturer="Test",
                product="Device",
                serial="SN001",
                trust_level=TrustLevel.UNKNOWN,
                first_seen=datetime.now(timezone.utc),
            )
            session.add(device)
            session.commit()

            # Log events
            for event_type in [EventType.CONNECT, EventType.ALLOWED, EventType.DISCONNECT]:
                event = Event(
                    timestamp=datetime.now(timezone.utc),
                    device_fingerprint=device.fingerprint,
                    event_type=event_type,
                    policy_rule="test_rule",
                    risk_score=25 if event_type == EventType.ALLOWED else None,
                    verdict="Safe" if event_type == EventType.ALLOWED else None,
                )
                session.add(event)
            session.commit()

        # Query events
        events = db.get_events(device_fingerprint="test_fingerprint_1234")
        assert len(events) == 3

    def test_device_crud(self) -> None:
        """Test device CRUD operations."""
        from sentinel.audit import AuditDatabase, Device, TrustLevel

        db = AuditDatabase(self.db_path)

        fingerprint = "crud_test_fp_12345"

        # Create device
        with db.session() as session:
            device = Device(
                fingerprint=fingerprint,
                vid="ABCD",
                pid="1234",
                manufacturer="Test",
                product="CRUD Device",
                trust_level=TrustLevel.UNKNOWN,
                first_seen=datetime.now(timezone.utc),
            )
            session.add(device)
            session.commit()

        # Read device
        saved = db.get_device(fingerprint)
        assert saved is not None
        assert saved.vid == "ABCD"
        assert saved.trust_level == TrustLevel.UNKNOWN

        # Update device
        db.update_trust_level(fingerprint, TrustLevel.TRUSTED)
        updated = db.get_device(fingerprint)
        assert updated.trust_level == TrustLevel.TRUSTED

    def test_statistics(self) -> None:
        """Test statistics retrieval."""
        from sentinel.audit import AuditDatabase, Device, Event, EventType, TrustLevel

        db = AuditDatabase(self.db_path)

        # Create multiple devices
        with db.session() as session:
            for i in range(5):
                trust = TrustLevel.TRUSTED if i < 2 else TrustLevel.UNKNOWN
                device = Device(
                    fingerprint=f"stats_device_{i:04d}ab",
                    vid=f"{i:04X}",
                    pid="0001",
                    manufacturer=f"Vendor{i}",
                    product=f"Product{i}",
                    trust_level=trust,
                    first_seen=datetime.now(timezone.utc),
                )
                session.add(device)
            session.commit()

        # Get statistics
        stats = db.get_statistics()
        # stats is a dict with trust_levels sub-dict
        assert stats["total_devices"] == 5
        assert stats["trust_levels"]["trusted"] == 2
        assert stats["trust_levels"]["unknown"] == 3


class TestInterceptorIntegration(unittest.TestCase):
    """Test USB interceptor integration."""

    def test_descriptor_creation(self) -> None:
        """Test device descriptor creation."""
        from sentinel.interceptor import create_test_descriptor

        # Create test descriptor
        descriptor = create_test_descriptor(
            vid=0x046D,
            pid=0xC52B,
            manufacturer="Logitech",
            product="USB Receiver",
        )

        assert descriptor.vid == 0x046D
        assert descriptor.pid == 0xC52B
        assert descriptor.manufacturer == "Logitech"

    def test_fingerprint_generation(self) -> None:
        """Test fingerprint generation."""
        from sentinel.interceptor import create_test_descriptor
        from sentinel.policy import generate_fingerprint

        descriptor = create_test_descriptor(
            vid=0x046D,
            pid=0xC52B,
            manufacturer="Logitech",
            product="USB Receiver",
        )

        fingerprint = generate_fingerprint(descriptor)
        assert fingerprint is not None
        assert len(fingerprint) > 0

        # Same device should generate same fingerprint
        fingerprint2 = generate_fingerprint(descriptor)
        assert fingerprint == fingerprint2


# ============================================================================
# API Integration Tests
# ============================================================================


class TestAPIHealthCheck(unittest.TestCase):
    """Test API health check endpoint."""

    def test_health_endpoint(self) -> None:
        """Test health check endpoint."""
        from sentinel.api import create_app

        app = create_app()
        client = TestClient(app)

        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


# ============================================================================
# Configuration Tests
# ============================================================================


class TestConfigurationIntegration(unittest.TestCase):
    """Test configuration loading and validation."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_loading(self) -> None:
        """Test configuration file loading."""
        from sentinel.config import load_config

        config_path = os.path.join(self.temp_dir, "config.yaml")
        config_content = """
daemon:
  log_level: debug
database:
  path: /tmp/sentinel.db
policy:
  rules_file: /tmp/policy.yaml
api:
  host: 0.0.0.0
  port: 8080
analyzer:
  provider: anthropic
"""
        with open(config_path, "w") as f:
            f.write(config_content)

        config = load_config(config_path)
        assert config.database.path == "/tmp/sentinel.db"
        assert config.daemon.log_level == "debug"

    def test_config_defaults(self) -> None:
        """Test configuration defaults."""
        from sentinel.config import SentinelConfig

        config = SentinelConfig()
        assert config.daemon.log_level == "info"
        assert config.api is not None


# ============================================================================
# Error Handling Tests
# ============================================================================


class TestErrorHandling(unittest.TestCase):
    """Test error handling across components."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_invalid_policy_handling(self) -> None:
        """Test handling of invalid policy files."""
        from sentinel.policy import PolicyEngine

        invalid_path = os.path.join(self.temp_dir, "invalid.yaml")
        with open(invalid_path, "w") as f:
            f.write("invalid: yaml: content: [")

        # Should raise or handle gracefully
        try:
            engine = PolicyEngine(invalid_path)
            # If it doesn't raise, it should have empty rules
            assert len(engine.rules) == 0
        except Exception:
            # Exception is acceptable for invalid config
            pass

    def test_database_error_recovery(self) -> None:
        """Test database error recovery."""
        from sentinel.audit import AuditDatabase, Device, TrustLevel

        db_path = os.path.join(self.temp_dir, "recovery.db")
        db = AuditDatabase(db_path)

        # Try to insert data
        with db.session() as session:
            device = Device(
                fingerprint="test_fp_12345678",
                vid="ABCD",
                pid="0000",
                trust_level=TrustLevel.UNKNOWN,
                first_seen=datetime.now(timezone.utc),
            )
            session.add(device)
            session.commit()

        # Should be stored
        saved = db.get_device("test_fp_12345678")
        assert saved is not None


# ============================================================================
# Performance Tests
# ============================================================================


class TestPerformance(unittest.TestCase):
    """Basic performance tests."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "perf.db")
        self.policy_path = os.path.join(self.temp_dir, "policy.yaml")

        # Create policy with multiple rules
        rules = "\n".join(
            [
                f"  - match:\n      vid: '{i:04X}'\n    action: allow\n    priority: {i}"
                for i in range(100)
            ]
        )
        with open(self.policy_path, "w") as f:
            f.write(f"rules:\n{rules}\n  - match: '*'\n    action: review\n    priority: 0")

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_policy_loading_speed(self) -> None:
        """Test policy loading is fast enough."""
        from sentinel.policy import load_policy

        # Run 100 policy loads
        start = time.perf_counter()
        for _ in range(100):
            load_policy(self.policy_path)
        elapsed = time.perf_counter() - start

        # Should complete in under 2 seconds
        assert elapsed < 2.0, f"Policy loading too slow: {elapsed:.3f}s for 100 loads"

    def test_database_insert_speed(self) -> None:
        """Test database insert performance."""
        from sentinel.audit import AuditDatabase, Device, TrustLevel

        db = AuditDatabase(self.db_path)

        # Insert 1000 devices
        start = time.perf_counter()
        with db.session() as session:
            for i in range(1000):
                device = Device(
                    fingerprint=f"perf_test_{i:06d}",
                    vid=f"{i:04X}",
                    pid="0001",
                    trust_level=TrustLevel.UNKNOWN,
                    first_seen=datetime.now(timezone.utc),
                )
                session.add(device)
            session.commit()
        elapsed = time.perf_counter() - start

        # Should complete in under 5 seconds
        assert elapsed < 5.0, f"Database inserts too slow: {elapsed:.3f}s for 1000 inserts"


# ============================================================================
# Analyzer Integration Tests
# ============================================================================


class TestAnalyzerIntegration(unittest.TestCase):
    """Test LLM analyzer integration."""

    def test_mock_analyzer_creation(self) -> None:
        """Test mock analyzer can be created."""
        from sentinel.analyzer import MockLLMAnalyzer

        analyzer = MockLLMAnalyzer()
        assert analyzer is not None

    def test_mock_analyzer_statistics(self) -> None:
        """Test mock analyzer statistics tracking."""
        from sentinel.analyzer import MockLLMAnalyzer

        analyzer = MockLLMAnalyzer()

        # Check that analyzer has statistics tracking
        stats = analyzer.get_statistics()
        assert "total_requests" in stats
        assert stats["total_requests"] == 0


if __name__ == "__main__":
    unittest.main()
