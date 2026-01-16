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

    # Range matching
    vid_list: list[str] | None = None  # Match any VID in list
    pid_list: list[str] | None = None  # Match any PID in list
    vid_range: tuple[str, str] | None = None  # VID range (min, max)

    # Class matching
    device_class: int | str | None = None  # Device or interface class
    interface_class: int | str | None = None  # Specific interface class
    class_list: list[int | str] | None = None  # Match any class in list

    # String pattern matching (regex)
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None

    # Boolean checks
    has_storage_endpoint: bool | None = None
    has_hid_endpoint: bool | None = None
    has_bulk_endpoint: bool | None = None
    is_composite: bool | None = None  # Multiple interfaces
    is_keyboard: bool | None = None
    is_mouse: bool | None = None

    # Numeric comparisons
    endpoint_count_gt: int | None = None
    endpoint_count_lt: int | None = None
    interface_count_gt: int | None = None
    interface_count_lt: int | None = None

    # State checks
    first_seen: bool | None = None
    trust_level: str | None = None  # Match devices with specific trust level

    # Wildcard match
    match_all: bool = False

    def is_wildcard(self) -> bool:
        """Check if this is a wildcard (match-all) condition."""
        return self.match_all

    def has_conditions(self) -> bool:
        """Check if any conditions are specified."""
        if self.match_all:
            return True
        for key, value in self.__dict__.items():
            if key != "match_all" and value is not None:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        if self.match_all:
            return {"match": "*"}

        result = {}
        for key, value in self.__dict__.items():
            if value is not None and key != "match_all":
                # Handle special serialization cases
                if key == "vid_range" and value:
                    result[key] = list(value)
                else:
                    result[key] = value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MatchCondition":
        """Create from dictionary."""
        if data == "*" or data.get("match") == "*":
            return cls(match_all=True)

        # Handle vid_range conversion
        vid_range = data.get("vid_range")
        if vid_range and isinstance(vid_range, list) and len(vid_range) == 2:
            vid_range = tuple(vid_range)

        return cls(
            vid=data.get("vid"),
            pid=data.get("pid"),
            vid_list=data.get("vid_list"),
            pid_list=data.get("pid_list"),
            vid_range=vid_range,
            device_class=data.get("device_class") or data.get("class"),
            interface_class=data.get("interface_class"),
            class_list=data.get("class_list"),
            manufacturer=data.get("manufacturer"),
            product=data.get("product"),
            serial=data.get("serial"),
            has_storage_endpoint=data.get("has_storage_endpoint"),
            has_hid_endpoint=data.get("has_hid_endpoint"),
            has_bulk_endpoint=data.get("has_bulk_endpoint"),
            is_composite=data.get("is_composite"),
            is_keyboard=data.get("is_keyboard"),
            is_mouse=data.get("is_mouse"),
            endpoint_count_gt=data.get("endpoint_count_gt"),
            endpoint_count_lt=data.get("endpoint_count_lt"),
            interface_count_gt=data.get("interface_count_gt"),
            interface_count_lt=data.get("interface_count_lt"),
            first_seen=data.get("first_seen"),
            trust_level=data.get("trust_level"),
        )


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
