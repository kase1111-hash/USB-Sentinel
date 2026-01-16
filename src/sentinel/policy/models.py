"""
Policy data models.

Defines the structure of policy rules and match conditions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(Enum):
    """Policy action to take on a device."""

    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"

    def __str__(self) -> str:
        return self.value


@dataclass
class MatchCondition:
    """
    Conditions for matching a device against a rule.

    All specified conditions must match (AND logic).
    None values are ignored (match any).
    """

    # Exact match conditions
    vid: str | None = None  # Vendor ID (hex string)
    pid: str | None = None  # Product ID (hex string)

    # Class matching
    device_class: int | str | None = None  # Device or interface class

    # String pattern matching (regex)
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None

    # Boolean checks
    has_storage_endpoint: bool | None = None
    has_hid_endpoint: bool | None = None

    # Numeric comparisons
    endpoint_count_gt: int | None = None

    # State checks
    first_seen: bool | None = None

    # Wildcard match
    match_all: bool = False

    def is_wildcard(self) -> bool:
        """Check if this is a wildcard (match-all) condition."""
        return self.match_all

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        for key, value in self.__dict__.items():
            if value is not None and key != "match_all":
                result[key] = value
        if self.match_all:
            return {"match": "*"}
        return result


@dataclass
class PolicyRule:
    """
    A single policy rule.

    Rules are evaluated in order; first match determines the action.
    """

    match: MatchCondition
    action: Action
    comment: str = ""
    priority: int = 0  # Lower priority = evaluated first

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "match": self.match.to_dict(),
            "action": str(self.action),
            "comment": self.comment,
        }


@dataclass
class Policy:
    """
    Complete policy configuration.

    Contains ordered list of rules to evaluate.
    """

    rules: list[PolicyRule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "rules": [rule.to_dict() for rule in self.rules]
        }


# USB Class code constants
class USBClass:
    """USB device/interface class codes."""

    INTERFACE_DEFINED = 0x00
    AUDIO = 0x01
    CDC = 0x02
    HID = 0x03
    PHYSICAL = 0x05
    IMAGE = 0x06
    PRINTER = 0x07
    MASS_STORAGE = 0x08
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    VIDEO = 0x0E
    WIRELESS = 0xE0
    MISCELLANEOUS = 0xEF
    APPLICATION_SPECIFIC = 0xFE
    VENDOR_SPECIFIC = 0xFF

    # High-risk classes
    HIGH_RISK = {HID, MASS_STORAGE, APPLICATION_SPECIFIC, VENDOR_SPECIFIC}

    @classmethod
    def from_name(cls, name: str) -> int | None:
        """Convert class name to code."""
        name_map = {
            "audio": cls.AUDIO,
            "cdc": cls.CDC,
            "communications": cls.CDC,
            "hid": cls.HID,
            "physical": cls.PHYSICAL,
            "image": cls.IMAGE,
            "printer": cls.PRINTER,
            "mass_storage": cls.MASS_STORAGE,
            "storage": cls.MASS_STORAGE,
            "hub": cls.HUB,
            "smart_card": cls.SMART_CARD,
            "video": cls.VIDEO,
            "wireless": cls.WIRELESS,
            "miscellaneous": cls.MISCELLANEOUS,
            "application_specific": cls.APPLICATION_SPECIFIC,
            "vendor_specific": cls.VENDOR_SPECIFIC,
        }
        return name_map.get(name.lower().replace(" ", "_").replace("-", "_"))
