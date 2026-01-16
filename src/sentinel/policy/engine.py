"""
Policy Engine.

Evaluates USB devices against policy rules and determines verdicts.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from sentinel.policy.fingerprint import FingerprintDatabase, generate_fingerprint
from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule, USBClass
from sentinel.policy.parser import PolicyParseError, load_policy, validate_policy

if TYPE_CHECKING:
    from sentinel.interceptor.descriptors import DeviceDescriptor


logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """
    Result of policy evaluation.

    Contains the verdict, matched rule, and evaluation details.
    """

    action: Action
    matched_rule: PolicyRule | None
    rule_index: int | None
    reason: str
    evaluation_time_ms: float = 0.0
    device_fingerprint: str | None = None

    @property
    def should_allow(self) -> bool:
        """Check if device should be allowed."""
        return self.action == Action.ALLOW

    @property
    def should_block(self) -> bool:
        """Check if device should be blocked."""
        return self.action == Action.BLOCK

    @property
    def needs_review(self) -> bool:
        """Check if device needs LLM review."""
        return self.action == Action.REVIEW

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "action": self.action.value,
            "rule_index": self.rule_index,
            "rule_comment": self.matched_rule.comment if self.matched_rule else None,
            "reason": self.reason,
            "evaluation_time_ms": self.evaluation_time_ms,
            "device_fingerprint": self.device_fingerprint,
        }


class RuleMatcher:
    """
    Matches devices against individual rules.

    Handles all match condition types including regex patterns.
    """

    def __init__(self, fingerprint_db: FingerprintDatabase | None = None) -> None:
        """
        Initialize the matcher.

        Args:
            fingerprint_db: Optional fingerprint database for first-seen checks
        """
        self.fingerprint_db = fingerprint_db or FingerprintDatabase()
        self._regex_cache: dict[str, re.Pattern] = {}

    def matches(
        self,
        condition: MatchCondition,
        device: DeviceDescriptor,
    ) -> bool:
        """
        Check if a device matches a condition.

        Args:
            condition: Match condition to check
            device: Device descriptor to match

        Returns:
            True if device matches all specified conditions
        """
        # Wildcard matches everything
        if condition.is_wildcard():
            return True

        # Check each condition (AND logic - all must match)

        # VID match
        if condition.vid is not None:
            if device.vid.lower() != condition.vid.lower():
                return False

        # PID match
        if condition.pid is not None:
            if device.pid.lower() != condition.pid.lower():
                return False

        # Device class match
        if condition.device_class is not None:
            class_code = self._normalize_class(condition.device_class)
            if not self._matches_class(device, class_code):
                return False

        # Manufacturer regex match
        if condition.manufacturer is not None:
            if not self._matches_regex(
                condition.manufacturer,
                device.manufacturer or "",
            ):
                return False

        # Product regex match
        if condition.product is not None:
            if not self._matches_regex(
                condition.product,
                device.product or "",
            ):
                return False

        # Serial regex match
        if condition.serial is not None:
            if not self._matches_regex(
                condition.serial,
                device.serial or "",
            ):
                return False

        # Has storage endpoint
        if condition.has_storage_endpoint is not None:
            has_storage = device.has_storage
            if condition.has_storage_endpoint != has_storage:
                return False

        # Has HID endpoint
        if condition.has_hid_endpoint is not None:
            has_hid = device.has_hid
            if condition.has_hid_endpoint != has_hid:
                return False

        # Endpoint count > N
        if condition.endpoint_count_gt is not None:
            if device.total_endpoints <= condition.endpoint_count_gt:
                return False

        # First seen check
        if condition.first_seen is not None:
            fingerprint = generate_fingerprint(device)
            is_first = self.fingerprint_db.is_first_seen(fingerprint)
            if condition.first_seen != is_first:
                return False

        # All conditions passed
        return True

    def _normalize_class(self, class_value: int | str) -> int:
        """Normalize class to integer code."""
        if isinstance(class_value, int):
            return class_value
        if isinstance(class_value, str):
            # Try name lookup
            code = USBClass.from_name(class_value)
            if code is not None:
                return code
            # Try hex/int parsing
            try:
                if class_value.startswith("0x"):
                    return int(class_value, 16)
                return int(class_value)
            except ValueError:
                return -1
        return -1

    def _matches_class(self, device: DeviceDescriptor, class_code: int) -> bool:
        """Check if device has the specified class."""
        # Check device class
        if device.device_class == class_code:
            return True
        # Check interface classes
        return any(
            intf.interface_class == class_code
            for intf in device.interfaces
        )

    def _matches_regex(self, pattern: str, value: str) -> bool:
        """Match value against regex pattern (cached)."""
        if pattern not in self._regex_cache:
            try:
                self._regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                logger.warning("Invalid regex pattern: %s", pattern)
                return False

        return bool(self._regex_cache[pattern].search(value))


class PolicyEngine:
    """
    Main policy evaluation engine.

    Evaluates devices against a policy and determines the action to take.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        fingerprint_db: FingerprintDatabase | None = None,
        default_action: Action = Action.REVIEW,
    ) -> None:
        """
        Initialize the policy engine.

        Args:
            policy: Policy to evaluate against
            fingerprint_db: Fingerprint database for first-seen checks
            default_action: Action when no rules match
        """
        self.policy = policy or Policy()
        self.fingerprint_db = fingerprint_db or FingerprintDatabase()
        self.default_action = default_action
        self.matcher = RuleMatcher(self.fingerprint_db)

        # Statistics
        self._evaluations = 0
        self._allowed = 0
        self._blocked = 0
        self._reviewed = 0

        # Hooks
        self._pre_evaluate_hooks: list[Callable] = []
        self._post_evaluate_hooks: list[Callable] = []

    @classmethod
    def from_file(
        cls,
        policy_path: str | Path,
        fingerprint_db: FingerprintDatabase | None = None,
    ) -> PolicyEngine:
        """
        Create engine from policy file.

        Args:
            policy_path: Path to policy YAML file
            fingerprint_db: Optional fingerprint database

        Returns:
            Configured PolicyEngine
        """
        policy = load_policy(policy_path)
        errors = validate_policy(policy)
        for error in errors:
            logger.warning("Policy validation: %s", error)
        return cls(policy=policy, fingerprint_db=fingerprint_db)

    def evaluate(self, device: DeviceDescriptor) -> EvaluationResult:
        """
        Evaluate a device against the policy.

        Args:
            device: Device descriptor to evaluate

        Returns:
            EvaluationResult with action and matched rule
        """
        start_time = datetime.utcnow()
        fingerprint = generate_fingerprint(device)

        # Run pre-evaluate hooks
        for hook in self._pre_evaluate_hooks:
            try:
                hook(device)
            except Exception as e:
                logger.error("Pre-evaluate hook error: %s", e)

        # Evaluate rules in order
        for i, rule in enumerate(self.policy.rules):
            if self.matcher.matches(rule.match, device):
                elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

                result = EvaluationResult(
                    action=rule.action,
                    matched_rule=rule,
                    rule_index=i,
                    reason=rule.comment or f"Matched rule {i}",
                    evaluation_time_ms=elapsed,
                    device_fingerprint=fingerprint,
                )

                self._update_stats(result.action)
                self._run_post_hooks(device, result)

                logger.debug(
                    "Device %s: %s (rule %d: %s)",
                    device.vid_pid, result.action.value, i, rule.comment
                )
                return result

        # No rule matched - use default action
        elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

        result = EvaluationResult(
            action=self.default_action,
            matched_rule=None,
            rule_index=None,
            reason="No matching rule - default action",
            evaluation_time_ms=elapsed,
            device_fingerprint=fingerprint,
        )

        self._update_stats(result.action)
        self._run_post_hooks(device, result)

        logger.debug(
            "Device %s: %s (default)",
            device.vid_pid, result.action.value
        )
        return result

    def _update_stats(self, action: Action) -> None:
        """Update evaluation statistics."""
        self._evaluations += 1
        if action == Action.ALLOW:
            self._allowed += 1
        elif action == Action.BLOCK:
            self._blocked += 1
        else:
            self._reviewed += 1

    def _run_post_hooks(
        self,
        device: DeviceDescriptor,
        result: EvaluationResult,
    ) -> None:
        """Run post-evaluate hooks."""
        for hook in self._post_evaluate_hooks:
            try:
                hook(device, result)
            except Exception as e:
                logger.error("Post-evaluate hook error: %s", e)

    def add_pre_evaluate_hook(self, hook: Callable) -> None:
        """Add a pre-evaluation hook."""
        self._pre_evaluate_hooks.append(hook)

    def add_post_evaluate_hook(self, hook: Callable) -> None:
        """Add a post-evaluation hook."""
        self._post_evaluate_hooks.append(hook)

    def reload_policy(self, policy_path: str | Path) -> list[str]:
        """
        Reload policy from file.

        Args:
            policy_path: Path to policy file

        Returns:
            List of validation warnings/errors
        """
        policy = load_policy(policy_path)
        errors = validate_policy(policy)
        self.policy = policy
        self.matcher = RuleMatcher(self.fingerprint_db)
        logger.info("Policy reloaded: %d rules", len(policy.rules))
        return errors

    def get_statistics(self) -> dict:
        """Get evaluation statistics."""
        return {
            "total_evaluations": self._evaluations,
            "allowed": self._allowed,
            "blocked": self._blocked,
            "reviewed": self._reviewed,
            "rule_count": len(self.policy.rules),
        }

    def reset_statistics(self) -> None:
        """Reset evaluation statistics."""
        self._evaluations = 0
        self._allowed = 0
        self._blocked = 0
        self._reviewed = 0

    def check_device_quick(
        self,
        vid: str,
        pid: str,
    ) -> Action | None:
        """
        Quick check for VID:PID without full descriptor.

        Args:
            vid: Vendor ID
            pid: Product ID

        Returns:
            Action if a VID:PID rule matches, None otherwise
        """
        for rule in self.policy.rules:
            if (
                rule.match.vid is not None
                and rule.match.pid is not None
                and rule.match.vid.lower() == vid.lower()
                and rule.match.pid.lower() == pid.lower()
            ):
                return rule.action
        return None

    def get_rules_for_class(self, class_code: int) -> list[PolicyRule]:
        """
        Get all rules that match a specific class.

        Args:
            class_code: USB class code

        Returns:
            List of matching rules
        """
        matching = []
        for rule in self.policy.rules:
            if rule.match.device_class is not None:
                rule_class = self.matcher._normalize_class(rule.match.device_class)
                if rule_class == class_code:
                    matching.append(rule)
        return matching


@dataclass
class PolicyBuilder:
    """
    Fluent builder for creating policies programmatically.
    """

    rules: list[PolicyRule] = field(default_factory=list)

    def allow(
        self,
        vid: str | None = None,
        pid: str | None = None,
        comment: str = "",
        **kwargs,
    ) -> PolicyBuilder:
        """Add an ALLOW rule."""
        return self._add_rule(Action.ALLOW, vid, pid, comment, **kwargs)

    def block(
        self,
        vid: str | None = None,
        pid: str | None = None,
        comment: str = "",
        **kwargs,
    ) -> PolicyBuilder:
        """Add a BLOCK rule."""
        return self._add_rule(Action.BLOCK, vid, pid, comment, **kwargs)

    def review(
        self,
        vid: str | None = None,
        pid: str | None = None,
        comment: str = "",
        **kwargs,
    ) -> PolicyBuilder:
        """Add a REVIEW rule."""
        return self._add_rule(Action.REVIEW, vid, pid, comment, **kwargs)

    def allow_class(self, class_name: str, comment: str = "") -> PolicyBuilder:
        """Add an ALLOW rule for a device class."""
        return self._add_rule(
            Action.ALLOW,
            device_class=class_name,
            comment=comment or f"Allow {class_name} devices",
        )

    def block_class(self, class_name: str, comment: str = "") -> PolicyBuilder:
        """Add a BLOCK rule for a device class."""
        return self._add_rule(
            Action.BLOCK,
            device_class=class_name,
            comment=comment or f"Block {class_name} devices",
        )

    def review_first_seen(self, comment: str = "") -> PolicyBuilder:
        """Add a REVIEW rule for first-seen devices."""
        return self._add_rule(
            Action.REVIEW,
            first_seen=True,
            comment=comment or "Review new devices",
        )

    def review_hid_with_storage(self, comment: str = "") -> PolicyBuilder:
        """Add a REVIEW rule for HID devices with storage."""
        return self._add_rule(
            Action.REVIEW,
            device_class="HID",
            has_storage_endpoint=True,
            comment=comment or "Review HID devices with storage",
        )

    def default_review(self, comment: str = "") -> PolicyBuilder:
        """Add a default REVIEW rule (wildcard)."""
        self.rules.append(PolicyRule(
            match=MatchCondition(match_all=True),
            action=Action.REVIEW,
            comment=comment or "Default: review unknown devices",
        ))
        return self

    def default_block(self, comment: str = "") -> PolicyBuilder:
        """Add a default BLOCK rule (wildcard)."""
        self.rules.append(PolicyRule(
            match=MatchCondition(match_all=True),
            action=Action.BLOCK,
            comment=comment or "Default: block unknown devices",
        ))
        return self

    def _add_rule(
        self,
        action: Action,
        vid: str | None = None,
        pid: str | None = None,
        comment: str = "",
        **kwargs,
    ) -> PolicyBuilder:
        """Add a rule with the given conditions."""
        condition = MatchCondition(
            vid=vid,
            pid=pid,
            device_class=kwargs.get("device_class"),
            manufacturer=kwargs.get("manufacturer"),
            product=kwargs.get("product"),
            serial=kwargs.get("serial"),
            has_storage_endpoint=kwargs.get("has_storage_endpoint"),
            has_hid_endpoint=kwargs.get("has_hid_endpoint"),
            endpoint_count_gt=kwargs.get("endpoint_count_gt"),
            first_seen=kwargs.get("first_seen"),
        )
        self.rules.append(PolicyRule(
            match=condition,
            action=action,
            comment=comment,
        ))
        return self

    def build(self) -> Policy:
        """Build the policy."""
        return Policy(rules=self.rules)

    def build_engine(
        self,
        fingerprint_db: FingerprintDatabase | None = None,
    ) -> PolicyEngine:
        """Build a PolicyEngine with this policy."""
        return PolicyEngine(
            policy=self.build(),
            fingerprint_db=fingerprint_db,
        )


def create_default_policy() -> Policy:
    """
    Create a sensible default policy.

    Returns:
        Default Policy with common rules
    """
    return (
        PolicyBuilder()
        # Known trusted vendors
        .allow("046d", comment="Logitech devices")
        .allow("045e", comment="Microsoft devices")
        .allow("05ac", comment="Apple devices")
        # Block known attack hardware
        .block("1a86", "7523", comment="CH340 - common attack hardware")
        .block("0483", "df11", comment="STM32 DFU mode")
        # Review suspicious patterns
        .review_hid_with_storage()
        .review_first_seen()
        # Default: review everything else
        .default_review()
        .build()
    )
