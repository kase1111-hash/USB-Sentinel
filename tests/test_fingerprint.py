"""
Tests for device fingerprinting and descriptor validation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
    create_test_descriptor,
)
from sentinel.interceptor.validator import (
    Anomaly,
    AnomalyType,
    DescriptorValidator,
    Severity,
    ValidationResult,
    validate_descriptor,
)
from sentinel.policy.fingerprint import (
    DeviceFingerprint,
    FingerprintDatabase,
    FingerprintGenerator,
    fingerprint_match,
    generate_fingerprint,
)


class TestFingerprintGenerator:
    """Tests for FingerprintGenerator."""

    def test_generate_standard(self) -> None:
        """Test standard mode fingerprint generation."""
        desc = create_test_descriptor(
            vid="046d",
            pid="c534",
            manufacturer="Logitech",
            product="USB Receiver",
        )

        generator = FingerprintGenerator(mode="standard")
        fp = generator.generate(desc)

        assert fp.fingerprint is not None
        assert len(fp.fingerprint) == 16
        assert fp.vid == "046d"
        assert fp.pid == "c534"

    def test_generate_strict(self) -> None:
        """Test strict mode includes serial."""
        desc = create_test_descriptor()
        desc.serial = "ABC123"

        generator = FingerprintGenerator(mode="strict")
        fp = generator.generate(desc)

        # Serial should be in components
        assert any("serial:" in c for c in fp.components)

    def test_generate_loose(self) -> None:
        """Test loose mode only includes VID/PID."""
        desc = create_test_descriptor(
            manufacturer="Test",
            product="Device",
        )

        generator = FingerprintGenerator(mode="loose")
        fp = generator.generate(desc)

        # Should only have vid and pid
        assert len(fp.components) == 2
        assert all(c.startswith("vid:") or c.startswith("pid:") for c in fp.components)

    def test_same_device_same_fingerprint(self) -> None:
        """Test that identical devices get same fingerprint."""
        desc1 = create_test_descriptor(vid="046d", pid="c534")
        desc2 = create_test_descriptor(vid="046d", pid="c534")

        fp1 = generate_fingerprint(desc1)
        fp2 = generate_fingerprint(desc2)

        assert fp1 == fp2

    def test_different_device_different_fingerprint(self) -> None:
        """Test that different devices get different fingerprints."""
        desc1 = create_test_descriptor(vid="046d", pid="c534")
        desc2 = create_test_descriptor(vid="046d", pid="c535")

        fp1 = generate_fingerprint(desc1)
        fp2 = generate_fingerprint(desc2)

        assert fp1 != fp2

    def test_invalid_mode(self) -> None:
        """Test that invalid mode raises error."""
        with pytest.raises(ValueError):
            FingerprintGenerator(mode="invalid")


class TestDeviceFingerprint:
    """Tests for DeviceFingerprint."""

    def test_equality_with_string(self) -> None:
        """Test fingerprint equality with string."""
        fp = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=["vid:046d", "pid:c534"],
            created_at=datetime.now(timezone.utc),
        )

        assert fp == "abc123"
        assert fp != "xyz789"

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        fp = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=["vid:046d", "pid:c534"],
            created_at=datetime.now(timezone.utc),
        )

        d = fp.to_dict()
        assert d["fingerprint"] == "abc123"
        assert d["vid"] == "046d"
        assert "created_at" in d


class TestFingerprintMatch:
    """Tests for fingerprint_match function."""

    def test_match_strings(self) -> None:
        """Test matching two strings."""
        assert fingerprint_match("abc123", "abc123") is True
        assert fingerprint_match("abc123", "xyz789") is False

    def test_match_fingerprint_objects(self) -> None:
        """Test matching fingerprint objects."""
        fp1 = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )
        fp2 = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )

        assert fingerprint_match(fp1, fp2) is True


class TestFingerprintDatabase:
    """Tests for FingerprintDatabase."""

    def test_add_and_get(self) -> None:
        """Test adding and retrieving fingerprints."""
        db = FingerprintDatabase()
        fp = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )

        db.add(fp, trust_level="trusted")

        assert db.exists("abc123")
        assert db.get("abc123") == fp
        assert db.get_trust_level("abc123") == "trusted"

    def test_is_first_seen(self) -> None:
        """Test first seen detection."""
        db = FingerprintDatabase()

        assert db.is_first_seen("new_fingerprint") is True

        fp = DeviceFingerprint(
            fingerprint="known",
            full_hash="known" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )
        db.add(fp)

        assert db.is_first_seen("known") is False

    def test_update_trust_level(self) -> None:
        """Test updating trust level."""
        db = FingerprintDatabase()
        fp = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )

        db.add(fp, trust_level="unknown")
        assert db.get_trust_level("abc123") == "unknown"

        db.set_trust_level("abc123", "trusted")
        assert db.get_trust_level("abc123") == "trusted"

    def test_timestamps(self) -> None:
        """Test first/last seen timestamps."""
        db = FingerprintDatabase()
        fp = DeviceFingerprint(
            fingerprint="abc123",
            full_hash="abc123" * 4,
            vid="046d",
            pid="c534",
            components=[],
            created_at=datetime.now(timezone.utc),
        )

        db.add(fp)
        first_seen = db.get_first_seen("abc123")
        last_seen = db.get_last_seen("abc123")

        assert first_seen is not None
        assert last_seen is not None

        # Update last seen
        db.update_last_seen("abc123")
        new_last_seen = db.get_last_seen("abc123")
        assert new_last_seen >= last_seen


class TestDescriptorValidator:
    """Tests for DescriptorValidator."""

    def test_validate_normal_device(self) -> None:
        """Test validation of normal device."""
        desc = create_test_descriptor(
            vid="046d",
            pid="c534",
            manufacturer="Logitech",
            product="USB Receiver",
        )

        result = validate_descriptor(desc)

        # Normal device should have low risk
        assert result.risk_score < 50

    def test_detect_known_signature(self) -> None:
        """Test detection of known attack signatures."""
        desc = create_test_descriptor(
            vid="1a86",
            pid="7523",
            manufacturer="QinHeng Electronics",
            product="CH340",
        )

        result = validate_descriptor(desc)

        assert result.has_anomalies
        assert any(
            a.anomaly_type == AnomalyType.ATTACK_SIGNATURE
            for a in result.anomalies
        )
        assert result.risk_score >= 50

    def test_detect_hid_storage_combo(self) -> None:
        """Test detection of HID + Storage combination."""
        desc = create_test_descriptor(
            vid="1234",
            pid="5678",
            manufacturer="Unknown",
            product="Suspicious Device",
            interfaces=[(0x03, 0, 0), (0x08, 6, 80)],  # HID + Mass Storage
        )

        result = validate_descriptor(desc)

        assert any(
            a.anomaly_type == AnomalyType.SUSPICIOUS_CLASS_COMBO
            for a in result.anomalies
        )

    def test_detect_missing_manufacturer(self) -> None:
        """Test detection of missing manufacturer."""
        desc = create_test_descriptor(
            manufacturer=None,
            product="Some Device",
        )

        result = validate_descriptor(desc)

        assert any(
            a.anomaly_type == AnomalyType.MISSING_MANUFACTURER
            for a in result.anomalies
        )

    def test_detect_generic_strings(self) -> None:
        """Test detection of generic strings."""
        desc = create_test_descriptor(
            manufacturer="USB Device",
            product="USB Device",
        )

        result = validate_descriptor(desc)

        assert any(
            a.anomaly_type == AnomalyType.GENERIC_STRINGS
            for a in result.anomalies
        )

    def test_detect_suspicious_patterns(self) -> None:
        """Test detection of suspicious string patterns."""
        desc = create_test_descriptor(
            manufacturer="ATMEL",
            product="Rubber Ducky",
        )

        result = validate_descriptor(desc)

        assert any(
            a.anomaly_type == AnomalyType.SUSPICIOUS_STRINGS
            or a.anomaly_type == AnomalyType.RUBBER_DUCKY_PATTERN
            for a in result.anomalies
        )


class TestValidationResult:
    """Tests for ValidationResult."""

    def test_add_anomaly(self) -> None:
        """Test adding anomalies."""
        result = ValidationResult(is_valid=True)

        result.add_anomaly(Anomaly(
            anomaly_type=AnomalyType.MISSING_MANUFACTURER,
            severity=Severity.MEDIUM,
            description="Test anomaly",
        ))

        assert result.has_anomalies
        assert len(result.anomalies) == 1
        assert result.risk_score > 0

    def test_highest_severity(self) -> None:
        """Test highest severity property."""
        result = ValidationResult(is_valid=True)

        result.add_anomaly(Anomaly(
            anomaly_type=AnomalyType.MISSING_PRODUCT,
            severity=Severity.LOW,
            description="Low severity",
        ))
        result.add_anomaly(Anomaly(
            anomaly_type=AnomalyType.ATTACK_SIGNATURE,
            severity=Severity.CRITICAL,
            description="Critical severity",
        ))

        assert result.highest_severity == Severity.CRITICAL

    def test_risk_score_calculation(self) -> None:
        """Test risk score calculation."""
        result = ValidationResult(is_valid=True)

        # Add multiple anomalies
        for _ in range(3):
            result.add_anomaly(Anomaly(
                anomaly_type=AnomalyType.MISSING_PRODUCT,
                severity=Severity.MEDIUM,
                description="Test",
            ))

        # 3 x MEDIUM (20) = 60
        assert result.risk_score >= 50

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        result = ValidationResult(is_valid=True)
        result.add_anomaly(Anomaly(
            anomaly_type=AnomalyType.MISSING_MANUFACTURER,
            severity=Severity.MEDIUM,
            description="Test",
        ))

        d = result.to_dict()
        assert "is_valid" in d
        assert "risk_score" in d
        assert "anomalies" in d
        assert len(d["anomalies"]) == 1


class TestDescriptorSerialization:
    """Tests for descriptor JSON serialization."""

    def test_device_to_json(self) -> None:
        """Test DeviceDescriptor to JSON."""
        desc = create_test_descriptor()
        json_str = desc.to_json()

        assert '"vid": "046d"' in json_str
        assert '"has_hid": true' in json_str

    def test_device_from_json(self) -> None:
        """Test DeviceDescriptor from JSON."""
        desc = create_test_descriptor(
            vid="1234",
            pid="5678",
            manufacturer="Test",
            product="Device",
        )

        json_str = desc.to_json()
        restored = DeviceDescriptor.from_json(json_str)

        assert restored.vid == "1234"
        assert restored.pid == "5678"
        assert restored.manufacturer == "Test"

    def test_interface_from_dict(self) -> None:
        """Test InterfaceDescriptor from dict."""
        data = {
            "interface_class": 3,
            "interface_subclass": 1,
            "interface_protocol": 1,
            "num_endpoints": 1,
            "endpoints": [
                {
                    "address_raw": 0x81,
                    "attributes_raw": 0x03,
                    "max_packet_size": 8,
                    "interval": 10,
                }
            ],
        }

        intf = InterfaceDescriptor.from_dict(data)

        assert intf.interface_class == 3
        assert intf.is_keyboard
        assert len(intf.endpoints) == 1

    def test_endpoint_from_dict(self) -> None:
        """Test EndpointDescriptor from dict."""
        data = {
            "address_raw": 0x81,
            "attributes_raw": 0x03,
            "max_packet_size": 8,
            "interval": 10,
        }

        ep = EndpointDescriptor.from_dict(data)

        assert ep.address == 0x81
        assert ep.direction == "IN"
        assert ep.transfer_type == "Interrupt"
