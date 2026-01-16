"""
Policy file parser.

Parses YAML policy files into Policy objects.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule, USBClass


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
        data = yaml.safe_load(f)

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
        action = Action(action_str.lower())
    except ValueError:
        raise PolicyParseError(f"Invalid action: {action_str}")

    # Parse optional fields
    comment = data.get("comment", "")
    priority = data.get("priority", 0)

    return PolicyRule(
        match=match,
        action=action,
        comment=comment,
        priority=priority,
    )


def parse_match_condition(data: Any) -> MatchCondition:
    """
    Parse match condition from data.

    Args:
        data: Match condition data (dict or '*' for wildcard)

    Returns:
        MatchCondition object
    """
    # Handle wildcard
    if data == "*":
        return MatchCondition(match_all=True)

    if not isinstance(data, dict):
        raise PolicyParseError("Match condition must be a dictionary or '*'")

    # Parse class field (can be string name or int)
    device_class = data.get("class")
    if isinstance(device_class, str):
        class_code = USBClass.from_name(device_class)
        if class_code is None:
            # Try parsing as hex
            try:
                class_code = int(device_class, 16) if device_class.startswith("0x") else int(device_class)
            except ValueError:
                raise PolicyParseError(f"Unknown device class: {device_class}")
        device_class = class_code

    return MatchCondition(
        vid=data.get("vid"),
        pid=data.get("pid"),
        device_class=device_class,
        manufacturer=data.get("manufacturer"),
        product=data.get("product"),
        serial=data.get("serial"),
        has_storage_endpoint=data.get("has_storage_endpoint"),
        has_hid_endpoint=data.get("has_hid_endpoint"),
        endpoint_count_gt=data.get("endpoint_count_gt"),
        first_seen=data.get("first_seen"),
    )


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
            errors.append(
                f"Warning: Rule {i} has same VID:PID as rule {vid_pid_rules[key]}"
            )
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
