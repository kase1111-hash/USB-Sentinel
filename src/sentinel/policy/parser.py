"""
Policy file parser.

Parses YAML policy files into Policy objects.

Parsing is strict on purpose: a match condition is an AND of its keys, so a
key the parser silently dropped (a typo, or a key it did not know about)
would widen the rule until it matched every device. Unknown keys, empty
matches and malformed values are therefore errors, not warnings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule, USBClass

# libyaml's parser is ~10x faster than the pure-Python one when available.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# `manufacturer: null` (and product/serial) in a policy means "the device
# reports no such string". The matcher compares against "" for missing
# strings, so this pattern matches missing, empty and whitespace-only values.
MISSING_STRING_PATTERN = r"^\s*$"

TRUST_LEVELS = ("trusted", "blocked", "unknown", "review")

_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{4}$")
_PATTERN_KEYS = ("manufacturer", "product", "serial")
_BOOL_KEYS = (
    "has_storage_endpoint",
    "has_hid_endpoint",
    "has_bulk_endpoint",
    "is_composite",
    "is_keyboard",
    "is_mouse",
    "first_seen",
)
_COUNT_KEYS = (
    "endpoint_count_gt",
    "endpoint_count_lt",
    "interface_count_gt",
    "interface_count_lt",
)
MATCH_KEYS = frozenset(
    {
        "vid",
        "pid",
        "vid_list",
        "pid_list",
        "vid_range",
        "class",
        "device_class",
        "interface_class",
        "class_list",
        "trust_level",
        *_PATTERN_KEYS,
        *_BOOL_KEYS,
        *_COUNT_KEYS,
    }
)
RULE_KEYS = frozenset({"match", "action", "comment", "priority", "name"})


class PolicyParseError(Exception):
    """Error parsing policy file."""

    pass


def load_policy(path: str | Path) -> Policy:
    """
    Load policy from YAML file.

    Args:
        path: Path to policy YAML file

    Returns:
        Policy object with parsed rules

    Raises:
        FileNotFoundError: If file doesn't exist
        PolicyParseError: If file contains invalid policy
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        try:
            data = yaml.load(f, Loader=_YAML_LOADER)
        except yaml.YAMLError as e:
            raise PolicyParseError(f"Invalid YAML in {path}: {e}") from e

    if data is None:
        return Policy(rules=[])

    return parse_policy(data)


def parse_policy(data: dict[str, Any]) -> Policy:
    """
    Parse policy from dictionary.

    Args:
        data: Dictionary with policy data

    Returns:
        Policy object
    """
    if not isinstance(data, dict):
        raise PolicyParseError("Policy must be a dictionary")

    rules_data = data.get("rules", [])
    if not isinstance(rules_data, list):
        raise PolicyParseError("'rules' must be a list")

    rules = []
    for i, rule_data in enumerate(rules_data):
        try:
            rule = parse_rule(rule_data)
            rules.append(rule)
        except Exception as e:
            raise PolicyParseError(f"Error parsing rule {i}: {e}") from e

    return Policy(rules=rules)


def parse_rule(data: dict[str, Any]) -> PolicyRule:
    """
    Parse a single rule from dictionary.

    Args:
        data: Dictionary with rule data

    Returns:
        PolicyRule object
    """
    if not isinstance(data, dict):
        raise PolicyParseError("Rule must be a dictionary")

    unknown = sorted(set(data) - RULE_KEYS)
    if unknown:
        raise PolicyParseError(
            f"Unknown rule key(s): {', '.join(map(str, unknown))} "
            f"(valid keys: {', '.join(sorted(RULE_KEYS))})"
        )

    # Parse match condition
    match_data = data.get("match")
    if match_data is None:
        raise PolicyParseError("Rule must have 'match' field")

    match = parse_match_condition(match_data)

    # Parse action
    action_str = data.get("action")
    if action_str is None:
        raise PolicyParseError("Rule must have 'action' field")

    try:
        action = Action(str(action_str).lower())
    except ValueError:
        raise PolicyParseError(
            f"Invalid action: {action_str!r} (expected allow, block or review)"
        ) from None

    # Parse optional fields
    comment = data.get("comment") or data.get("name") or ""
    priority = data.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise PolicyParseError(f"'priority' must be an integer, got {priority!r}")

    return PolicyRule(
        match=match,
        action=action,
        comment=str(comment),
        priority=priority,
    )


def parse_match_condition(data: Any) -> MatchCondition:
    """
    Parse match condition from data.

    Args:
        data: Match condition data (dict or '*' for wildcard)

    Returns:
        MatchCondition object

    Raises:
        PolicyParseError: On unknown keys, empty conditions or invalid values
    """
    # Handle wildcard
    if data == "*":
        return MatchCondition(match_all=True)

    if not isinstance(data, dict):
        raise PolicyParseError("Match condition must be a dictionary or '*'")

    if not data:
        raise PolicyParseError("Empty match condition; use match: '*' to match every device")

    unknown = sorted(set(data) - MATCH_KEYS)
    if unknown:
        raise PolicyParseError(
            f"Unknown match key(s): {', '.join(map(str, unknown))} "
            f"(valid keys: {', '.join(sorted(MATCH_KEYS))})"
        )

    if "class" in data and "device_class" in data:
        raise PolicyParseError("Use either 'class' or 'device_class', not both")

    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key in ("vid", "pid"):
            kwargs[key] = _parse_hex_id(key, value)
        elif key in ("vid_list", "pid_list"):
            kwargs[key] = [_parse_hex_id(key, v) for v in _require_list(key, value)]
        elif key == "vid_range":
            bounds = _require_list(key, value)
            if len(bounds) != 2:
                raise PolicyParseError("'vid_range' must be a list of two VIDs [min, max]")
            kwargs[key] = (_parse_hex_id(key, bounds[0]), _parse_hex_id(key, bounds[1]))
        elif key in ("class", "device_class"):
            kwargs["device_class"] = parse_usb_class(value)
        elif key == "interface_class":
            kwargs[key] = parse_usb_class(value)
        elif key == "class_list":
            kwargs[key] = [parse_usb_class(v) for v in _require_list(key, value)]
        elif key in _PATTERN_KEYS:
            kwargs[key] = _parse_pattern(key, value)
        elif key in _BOOL_KEYS:
            if not isinstance(value, bool):
                raise PolicyParseError(f"'{key}' must be true or false, got {value!r}")
            kwargs[key] = value
        elif key in _COUNT_KEYS:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise PolicyParseError(f"'{key}' must be a non-negative integer, got {value!r}")
            kwargs[key] = value
        elif key == "trust_level":
            if value not in TRUST_LEVELS:
                raise PolicyParseError(
                    f"'trust_level' must be one of {', '.join(TRUST_LEVELS)}, got {value!r}"
                )
            kwargs[key] = value

    return MatchCondition(**kwargs)


def parse_usb_class(value: Any) -> int:
    """
    Parse a USB class given as a name ('HID'), number (3) or hex string ('0x03').

    Raises:
        PolicyParseError: If the value is not a known class name or a code 0x00-0xFF
    """
    if isinstance(value, bool):
        raise PolicyParseError(f"Invalid USB class: {value!r}")
    if isinstance(value, int):
        code = value
    elif isinstance(value, str):
        named = USBClass.from_name(value)
        if named is not None:
            return named
        try:
            code = int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            raise PolicyParseError(f"Unknown USB class: {value!r}") from None
    else:
        raise PolicyParseError(f"Invalid USB class: {value!r}")

    if not 0x00 <= code <= 0xFF:
        raise PolicyParseError(f"USB class out of range (0x00-0xFF): {value!r}")
    return code


def _parse_hex_id(key: str, value: Any) -> str:
    """Validate a 4-digit hex VID/PID string and normalize it to lowercase."""
    if isinstance(value, int) and not isinstance(value, bool):
        # YAML reads unquoted 1234 as decimal and 0400 as octal, so the
        # intended hex value cannot be recovered reliably.
        raise PolicyParseError(
            f"'{key}' must be a quoted 4-digit hex string such as '046d' "
            f"(YAML read the unquoted value as the number {value})"
        )
    if not isinstance(value, str) or not _HEX_ID_RE.match(value):
        raise PolicyParseError(f"'{key}' must be a 4-digit hex string, got {value!r}")
    return value.lower()


def _parse_pattern(key: str, value: Any) -> str:
    """Validate a regex string field; null means 'string is missing'."""
    if value is None:
        return MISSING_STRING_PATTERN
    if not isinstance(value, str):
        raise PolicyParseError(f"'{key}' must be a regex string or null, got {value!r}")
    try:
        re.compile(value)
    except re.error as e:
        raise PolicyParseError(f"Invalid regex in '{key}': {e}") from e
    return value


def _require_list(key: str, value: Any) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise PolicyParseError(f"'{key}' must be a non-empty list")
    return value


def validate_policy(policy: Policy) -> list[str]:
    """
    Validate a policy and return list of errors/warnings.

    Args:
        policy: Policy to validate

    Returns:
        List of error/warning messages
    """
    errors: list[str] = []

    if not policy.rules:
        errors.append("Warning: Policy has no rules")
        return errors

    # Check for duplicate VID:PID rules
    vid_pid_rules: dict[tuple[str | None, str | None], int] = {}
    for i, rule in enumerate(policy.rules):
        key = (rule.match.vid, rule.match.pid)
        if key != (None, None) and key in vid_pid_rules:
            errors.append(f"Warning: Rule {i} has same VID:PID as rule {vid_pid_rules[key]}")
        vid_pid_rules[key] = i

    # Check regex patterns are valid
    for i, rule in enumerate(policy.rules):
        for field in ["manufacturer", "product", "serial"]:
            pattern = getattr(rule.match, field)
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"Rule {i}: Invalid regex in '{field}': {e}")

    # Check for unreachable rules (wildcard not at end)
    for i, rule in enumerate(policy.rules):
        if rule.match.is_wildcard() and i < len(policy.rules) - 1:
            errors.append(
                f"Warning: Wildcard rule at position {i} makes subsequent rules unreachable"
            )

    return errors
