"""
Device Fingerprinting.

Generates stable, unique fingerprints for USB device identification.
Fingerprints are used to track devices across connections and for
policy matching.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.interceptor.descriptors import DeviceDescriptor


@dataclass
class DeviceFingerprint:
    """
    USB device fingerprint.

    Contains the fingerprint hash and metadata about how it was generated.
    """

    fingerprint: str  # Short hash (16 chars)
    full_hash: str  # Full SHA-256 hash
    vid: str
    pid: str
    components: list[str]  # Components used to generate fingerprint
    created_at: datetime

    def __str__(self) -> str:
        return self.fingerprint

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DeviceFingerprint):
            return self.fingerprint == other.fingerprint
        if isinstance(other, str):
            return self.fingerprint == other
        return False

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "fingerprint": self.fingerprint,
            "full_hash": self.full_hash,
            "vid": self.vid,
            "pid": self.pid,
            "components": self.components,
            "created_at": self.created_at.isoformat(),
        }


class FingerprintGenerator:
    """
    Generates device fingerprints.

    Fingerprints are generated from device descriptor attributes.
    The fingerprint should be stable across reconnections but unique
    enough to distinguish different device instances.
    """

    # Fingerprint modes
    MODE_STRICT = "strict"  # Include serial number (unique per device instance)
    MODE_STANDARD = "standard"  # VID/PID/class/strings (identifies device model)
    MODE_LOOSE = "loose"  # VID/PID only (identifies device type)

    def __init__(self, mode: str = MODE_STANDARD) -> None:
        """
        Initialize fingerprint generator.

        Args:
            mode: Fingerprint mode (strict, standard, loose)
        """
        if mode not in (self.MODE_STRICT, self.MODE_STANDARD, self.MODE_LOOSE):
            raise ValueError(f"Invalid mode: {mode}")
        self.mode = mode

    def generate(self, descriptor: DeviceDescriptor) -> DeviceFingerprint:
        """
        Generate fingerprint for a device.

        Args:
            descriptor: Device descriptor to fingerprint

        Returns:
            DeviceFingerprint with hash and metadata
        """
        components = self._get_components(descriptor)
        data = "|".join(components).encode("utf-8")
        full_hash = hashlib.sha256(data).hexdigest()

        return DeviceFingerprint(
            fingerprint=full_hash[:16],
            full_hash=full_hash,
            vid=descriptor.vid,
            pid=descriptor.pid,
            components=components,
            created_at=datetime.now(timezone.utc),
        )

    def _get_components(self, descriptor: DeviceDescriptor) -> list[str]:
        """
        Get components for fingerprint based on mode.

        Args:
            descriptor: Device descriptor

        Returns:
            List of string components
        """
        components = [
            f"vid:{descriptor.vid}",
            f"pid:{descriptor.pid}",
        ]

        if self.mode in (self.MODE_STANDARD, self.MODE_STRICT):
            # Add device class info
            components.append(f"class:{descriptor.device_class}")

            # Add interface classes (sorted for stability)
            interface_classes = sorted(
                intf.interface_class for intf in descriptor.interfaces
            )
            components.append(f"ifaces:{','.join(map(str, interface_classes))}")

            # Add manufacturer and product strings (normalized)
            if descriptor.manufacturer:
                components.append(f"mfr:{self._normalize(descriptor.manufacturer)}")
            if descriptor.product:
                components.append(f"prod:{self._normalize(descriptor.product)}")

        if self.mode == self.MODE_STRICT:
            # Add serial number for unique instance identification
            if descriptor.serial:
                components.append(f"serial:{descriptor.serial}")

        return components

    def _normalize(self, s: str) -> str:
        """Normalize string for consistent fingerprinting."""
        return s.strip().lower()


def generate_fingerprint(
    descriptor: DeviceDescriptor,
    mode: str = FingerprintGenerator.MODE_STANDARD,
) -> str:
    """
    Generate fingerprint hash for a device.

    Convenience function for quick fingerprint generation.

    Args:
        descriptor: Device descriptor
        mode: Fingerprint mode

    Returns:
        16-character fingerprint hash
    """
    generator = FingerprintGenerator(mode=mode)
    return generator.generate(descriptor).fingerprint


def fingerprint_match(fp1: str | DeviceFingerprint, fp2: str | DeviceFingerprint) -> bool:
    """
    Check if two fingerprints match.

    Args:
        fp1: First fingerprint
        fp2: Second fingerprint

    Returns:
        True if fingerprints match
    """
    s1 = fp1.fingerprint if isinstance(fp1, DeviceFingerprint) else fp1
    s2 = fp2.fingerprint if isinstance(fp2, DeviceFingerprint) else fp2
    return s1 == s2


class FingerprintDatabase:
    """
    In-memory fingerprint database for quick lookups.

    Used to track seen devices and their trust status.
    """

    def __init__(self) -> None:
        self._fingerprints: dict[str, DeviceFingerprint] = {}
        self._trust_levels: dict[str, str] = {}
        self._first_seen: dict[str, datetime] = {}
        self._last_seen: dict[str, datetime] = {}

    def add(
        self,
        fingerprint: DeviceFingerprint,
        trust_level: str = "unknown",
    ) -> None:
        """
        Add a fingerprint to the database.

        Args:
            fingerprint: Fingerprint to add
            trust_level: Initial trust level
        """
        fp_str = fingerprint.fingerprint
        now = datetime.now(timezone.utc)

        if fp_str not in self._fingerprints:
            self._first_seen[fp_str] = now

        self._fingerprints[fp_str] = fingerprint
        self._trust_levels[fp_str] = trust_level
        self._last_seen[fp_str] = now

    def get(self, fingerprint: str) -> DeviceFingerprint | None:
        """
        Get fingerprint record.

        Args:
            fingerprint: Fingerprint hash to look up

        Returns:
            DeviceFingerprint or None if not found
        """
        return self._fingerprints.get(fingerprint)

    def exists(self, fingerprint: str) -> bool:
        """Check if fingerprint exists in database."""
        return fingerprint in self._fingerprints

    def is_first_seen(self, fingerprint: str) -> bool:
        """Check if this is the first time seeing this fingerprint."""
        return fingerprint not in self._fingerprints

    def get_trust_level(self, fingerprint: str) -> str | None:
        """Get trust level for fingerprint."""
        return self._trust_levels.get(fingerprint)

    def set_trust_level(self, fingerprint: str, level: str) -> None:
        """Set trust level for fingerprint."""
        if fingerprint in self._fingerprints:
            self._trust_levels[fingerprint] = level

    def get_first_seen(self, fingerprint: str) -> datetime | None:
        """Get first seen timestamp."""
        return self._first_seen.get(fingerprint)

    def get_last_seen(self, fingerprint: str) -> datetime | None:
        """Get last seen timestamp."""
        return self._last_seen.get(fingerprint)

    def update_last_seen(self, fingerprint: str) -> None:
        """Update last seen timestamp."""
        if fingerprint in self._fingerprints:
            self._last_seen[fingerprint] = datetime.now(timezone.utc)

    def all_fingerprints(self) -> list[str]:
        """Get all fingerprints in database."""
        return list(self._fingerprints.keys())

    def count(self) -> int:
        """Get number of fingerprints in database."""
        return len(self._fingerprints)

    def to_dict(self) -> dict:
        """Export database to dictionary."""
        return {
            fp: {
                "fingerprint": self._fingerprints[fp].to_dict(),
                "trust_level": self._trust_levels[fp],
                "first_seen": self._first_seen[fp].isoformat(),
                "last_seen": self._last_seen[fp].isoformat(),
            }
            for fp in self._fingerprints
        }

    def to_json(self) -> str:
        """Export database to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
