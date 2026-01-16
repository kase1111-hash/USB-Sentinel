"""
Tests for Audit Database module.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from sentinel.audit.database import AuditDatabase, create_database
from sentinel.audit.models import EventType, TrustLevel
from sentinel.audit.schemas import (
    DeviceCreate,
    DeviceResponse,
    DeviceUpdate,
    EventCreate,
    EventResponse,
    TrustLevel as SchemaTrustLevel,
    device_to_response,
    event_to_response,
)


class TestAuditDatabase:
    """Tests for AuditDatabase class."""

    def test_create_database(self, temp_dir: Path) -> None:
        """Test database creation."""
        db_path = temp_dir / "test.db"
        db = AuditDatabase(db_path)

        assert db_path.exists()
        db.close()

    def test_add_device(self, test_db: AuditDatabase) -> None:
        """Test adding a device."""
        device = test_db.add_device(
            fingerprint="abc123def456",
            vid="046d",
            pid="c534",
            manufacturer="Logitech",
            product="USB Receiver",
        )

        assert device.fingerprint == "abc123def456"
        assert device.vid == "046d"
        assert device.manufacturer == "Logitech"
        assert device.trust_level == TrustLevel.UNKNOWN.value

    def test_get_device(self, test_db: AuditDatabase) -> None:
        """Test retrieving a device."""
        # Add device
        test_db.add_device(
            fingerprint="test_fingerprint",
            vid="1234",
            pid="5678",
        )

        # Retrieve
        device = test_db.get_device("test_fingerprint")

        assert device is not None
        assert device.fingerprint == "test_fingerprint"

    def test_get_device_not_found(self, test_db: AuditDatabase) -> None:
        """Test retrieving non-existent device."""
        device = test_db.get_device("nonexistent")
        assert device is None

    def test_update_trust_level(self, test_db: AuditDatabase) -> None:
        """Test updating device trust level."""
        test_db.add_device(
            fingerprint="update_test",
            vid="1234",
            pid="5678",
        )

        result = test_db.update_trust_level("update_test", TrustLevel.TRUSTED)
        assert result is True

        device = test_db.get_device("update_test")
        assert device.trust_level == TrustLevel.TRUSTED.value

    def test_update_trust_level_not_found(self, test_db: AuditDatabase) -> None:
        """Test updating non-existent device."""
        result = test_db.update_trust_level("nonexistent", TrustLevel.BLOCKED)
        assert result is False

    def test_get_all_devices(self, test_db: AuditDatabase) -> None:
        """Test getting all devices."""
        # Add multiple devices
        for i in range(5):
            test_db.add_device(
                fingerprint=f"device_{i}",
                vid=f"000{i}",
                pid="0000",
            )

        devices = test_db.get_all_devices()
        assert len(devices) == 5

    def test_get_devices_filtered_by_trust(self, test_db: AuditDatabase) -> None:
        """Test filtering devices by trust level."""
        # Add devices with different trust levels
        test_db.add_device(
            fingerprint="trusted_1",
            vid="0001",
            pid="0000",
            trust_level=TrustLevel.TRUSTED,
        )
        test_db.add_device(
            fingerprint="blocked_1",
            vid="0002",
            pid="0000",
            trust_level=TrustLevel.BLOCKED,
        )
        test_db.add_device(
            fingerprint="unknown_1",
            vid="0003",
            pid="0000",
        )

        trusted = test_db.get_all_devices(trust_level=TrustLevel.TRUSTED)
        assert len(trusted) == 1
        assert trusted[0].fingerprint == "trusted_1"

    def test_device_exists(self, test_db: AuditDatabase) -> None:
        """Test checking device existence."""
        test_db.add_device(fingerprint="exists_test", vid="1234", pid="5678")

        assert test_db.device_exists("exists_test") is True
        assert test_db.device_exists("nonexistent") is False

    def test_count_devices(self, test_db: AuditDatabase) -> None:
        """Test counting devices."""
        for i in range(3):
            test_db.add_device(
                fingerprint=f"count_device_{i}",
                vid=f"000{i}",
                pid="0000",
            )

        assert test_db.count_devices() == 3


class TestEventLogging:
    """Tests for event logging."""

    def test_log_event(self, test_db: AuditDatabase) -> None:
        """Test logging an event."""
        # First add device
        test_db.add_device(
            fingerprint="event_test_device",
            vid="1234",
            pid="5678",
        )

        # Log event
        event = test_db.log_event(
            device_fingerprint="event_test_device",
            event_type=EventType.CONNECT,
            verdict="allow",
            risk_score=15,
        )

        assert event.id is not None
        assert event.device_fingerprint == "event_test_device"
        assert event.event_type == EventType.CONNECT.value
        assert event.risk_score == 15

    def test_log_event_with_descriptor(self, test_db: AuditDatabase) -> None:
        """Test logging event with raw descriptor."""
        test_db.add_device(
            fingerprint="desc_event_device",
            vid="1234",
            pid="5678",
        )

        descriptor = {"vid": "1234", "pid": "5678", "product": "Test"}
        event = test_db.log_event(
            device_fingerprint="desc_event_device",
            event_type=EventType.ALLOWED,
            raw_descriptor=descriptor,
        )

        assert event.raw_descriptor is not None
        parsed = json.loads(event.raw_descriptor)
        assert parsed["vid"] == "1234"

    def test_log_event_device_not_found(self, test_db: AuditDatabase) -> None:
        """Test logging event for non-existent device."""
        with pytest.raises(ValueError, match="Device not found"):
            test_db.log_event(
                device_fingerprint="nonexistent",
                event_type=EventType.CONNECT,
            )

    def test_get_events(self, test_db: AuditDatabase) -> None:
        """Test querying events."""
        # Setup
        test_db.add_device(fingerprint="events_device", vid="1234", pid="5678")

        for i in range(5):
            test_db.log_event(
                device_fingerprint="events_device",
                event_type=EventType.CONNECT if i % 2 == 0 else EventType.DISCONNECT,
            )

        # Query all
        events = test_db.get_events(device_fingerprint="events_device")
        assert len(events) == 5

        # Query by type
        connects = test_db.get_events(
            device_fingerprint="events_device",
            event_type=EventType.CONNECT,
        )
        assert len(connects) == 3

    def test_get_recent_events(self, test_db: AuditDatabase) -> None:
        """Test getting recent events."""
        test_db.add_device(fingerprint="recent_device", vid="1234", pid="5678")

        test_db.log_event(
            device_fingerprint="recent_device",
            event_type=EventType.CONNECT,
        )

        events = test_db.get_recent_events(hours=1)
        assert len(events) >= 1

    def test_count_events(self, test_db: AuditDatabase) -> None:
        """Test counting events."""
        test_db.add_device(fingerprint="count_events_device", vid="1234", pid="5678")

        for _ in range(3):
            test_db.log_event(
                device_fingerprint="count_events_device",
                event_type=EventType.CONNECT,
            )

        count = test_db.count_events(device_fingerprint="count_events_device")
        assert count == 3


class TestDatabaseStatistics:
    """Tests for database statistics."""

    def test_get_statistics(self, test_db: AuditDatabase) -> None:
        """Test getting database statistics."""
        # Add some data
        test_db.add_device(fingerprint="stats_device", vid="1234", pid="5678")
        test_db.log_event(
            device_fingerprint="stats_device",
            event_type=EventType.CONNECT,
        )

        stats = test_db.get_statistics()

        assert "total_devices" in stats
        assert "total_events" in stats
        assert "trust_levels" in stats
        assert "event_types" in stats
        assert stats["total_devices"] >= 1
        assert stats["total_events"] >= 1


class TestDatabaseExportBackup:
    """Tests for export and backup functionality."""

    def test_export_to_json(self, test_db: AuditDatabase, temp_dir: Path) -> None:
        """Test exporting database to JSON."""
        # Add data
        test_db.add_device(
            fingerprint="export_device",
            vid="1234",
            pid="5678",
            manufacturer="Test",
        )
        test_db.log_event(
            device_fingerprint="export_device",
            event_type=EventType.CONNECT,
        )

        # Export
        export_path = temp_dir / "export.json"
        test_db.export_to_json(export_path)

        # Verify
        assert export_path.exists()
        with open(export_path) as f:
            data = json.load(f)

        assert "devices" in data
        assert "events" in data
        assert len(data["devices"]) >= 1

    def test_backup(self, test_db: AuditDatabase, temp_dir: Path) -> None:
        """Test database backup."""
        # Add data
        test_db.add_device(fingerprint="backup_device", vid="1234", pid="5678")

        # Backup
        backup_path = test_db.backup()

        assert backup_path.exists()
        assert backup_path.stat().st_size > 0


class TestDatabaseIntegrity:
    """Tests for database integrity features."""

    def test_compute_integrity_hash(self, test_db: AuditDatabase) -> None:
        """Test computing integrity hash."""
        test_db.add_device(fingerprint="hash_device", vid="1234", pid="5678")
        test_db.log_event(
            device_fingerprint="hash_device",
            event_type=EventType.CONNECT,
        )

        hash1 = test_db.compute_integrity_hash()
        hash2 = test_db.compute_integrity_hash()

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex

    def test_verify_integrity(self, test_db: AuditDatabase) -> None:
        """Test integrity verification."""
        result = test_db.verify_integrity()
        assert result is True

    def test_verify_integrity_with_hash(self, test_db: AuditDatabase) -> None:
        """Test integrity verification with expected hash."""
        test_db.add_device(fingerprint="integrity_device", vid="1234", pid="5678")
        test_db.log_event(
            device_fingerprint="integrity_device",
            event_type=EventType.CONNECT,
        )

        expected = test_db.compute_integrity_hash()
        result = test_db.verify_integrity(expected_hash=expected)

        assert result is True


class TestPydanticSchemas:
    """Tests for Pydantic schemas."""

    def test_device_create_validation(self) -> None:
        """Test DeviceCreate validation."""
        device = DeviceCreate(
            fingerprint="abc123def456ghij",
            vid="046D",  # Should be normalized to lowercase
            pid="c534",
            manufacturer="Logitech",
        )

        assert device.vid == "046d"
        assert device.fingerprint == "abc123def456ghij"

    def test_device_create_invalid_vid(self) -> None:
        """Test DeviceCreate rejects invalid VID."""
        with pytest.raises(ValueError):
            DeviceCreate(
                fingerprint="abc123def456ghij",
                vid="invalid",  # Not 4 hex chars
                pid="c534",
            )

    def test_device_update(self) -> None:
        """Test DeviceUpdate schema."""
        update = DeviceUpdate(
            trust_level=SchemaTrustLevel.TRUSTED,
            notes="Verified device",
        )

        assert update.trust_level == SchemaTrustLevel.TRUSTED
        assert update.notes == "Verified device"

    def test_event_create(self) -> None:
        """Test EventCreate schema."""
        event = EventCreate(
            device_fingerprint="abc123def456ghij",
            event_type="connect",
            risk_score=25,
        )

        assert event.risk_score == 25

    def test_event_create_invalid_risk_score(self) -> None:
        """Test EventCreate rejects invalid risk score."""
        with pytest.raises(ValueError):
            EventCreate(
                device_fingerprint="abc123def456ghij",
                event_type="connect",
                risk_score=150,  # > 100
            )

    def test_device_to_response(self, test_db: AuditDatabase) -> None:
        """Test converting Device model to response schema."""
        device = test_db.add_device(
            fingerprint="response_test",
            vid="1234",
            pid="5678",
            manufacturer="Test",
            product="Device",
        )

        response = device_to_response(device, event_count=5)

        assert response.fingerprint == "response_test"
        assert response.event_count == 5
        assert response.display_name == "Device"

    def test_event_to_response(self, test_db: AuditDatabase) -> None:
        """Test converting Event model to response schema."""
        test_db.add_device(fingerprint="event_response_test", vid="1234", pid="5678")
        event = test_db.log_event(
            device_fingerprint="event_response_test",
            event_type=EventType.BLOCKED,
            verdict="block",
            risk_score=85,
        )

        response = event_to_response(event)

        assert response.event_type.value == "blocked"
        assert response.risk_score == 85


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_db(temp_dir: Path) -> AuditDatabase:
    """Create a test database."""
    db_path = temp_dir / "test_audit.db"
    db = AuditDatabase(db_path)
    yield db
    db.close()
