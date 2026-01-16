"""
Tests for Policy Engine module.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinel.interceptor.descriptors import (
    DeviceDescriptor,
    EndpointDescriptor,
    InterfaceDescriptor,
    create_test_descriptor,
)
from sentinel.policy.engine import (
    EvaluationResult,
    PolicyBuilder,
    PolicyEngine,
    RuleMatcher,
    create_default_policy,
)
from sentinel.policy.fingerprint import FingerprintDatabase
from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule, USBClass
from sentinel.policy.parser import (
    PolicyParseError,
    load_policy,
    parse_match_condition,
    parse_policy,
    parse_rule,
    validate_policy,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_device() -> DeviceDescriptor:
    """Create a sample device descriptor."""
    return create_test_descriptor(
        vid="046d",
        pid="c534",
        manufacturer="Logitech",
        product="USB Receiver",
        interfaces=[(0x03, 0x01, 0x02)],  # HID mouse
    )


@pytest.fixture
def attack_device() -> DeviceDescriptor:
    """Create a suspicious attack-like device."""
    return create_test_descriptor(
        vid="1a86",
        pid="7523",
        manufacturer="USB Device",
        product="CH340",
        interfaces=[(0x03, 0, 0), (0x08, 6, 80)],  # HID + Storage
    )


@pytest.fixture
def sample_policy() -> Policy:
    """Create a sample policy for testing."""
    return (
        PolicyBuilder()
        .allow("046d", "c534", comment="Logitech Receiver")
        .block("1a86", "7523", comment="CH340 attack hardware")
        .review(device_class="HID", has_storage_endpoint=True, comment="Suspicious combo")
        .default_review()
        .build()
    )


@pytest.fixture
def policy_engine(sample_policy: Policy) -> PolicyEngine:
    """Create a policy engine for testing."""
    return PolicyEngine(policy=sample_policy)


# =============================================================================
# Test MatchCondition
# =============================================================================


class TestMatchCondition:
    """Tests for MatchCondition."""

    def test_wildcard(self) -> None:
        """Test wildcard condition."""
        condition = MatchCondition(match_all=True)
        assert condition.is_wildcard() is True

    def test_not_wildcard(self) -> None:
        """Test non-wildcard condition."""
        condition = MatchCondition(vid="046d")
        assert condition.is_wildcard() is False

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        condition = MatchCondition(vid="046d", pid="c534")
        d = condition.to_dict()

        assert d["vid"] == "046d"
        assert d["pid"] == "c534"
        assert "manufacturer" not in d  # None values excluded

    def test_to_dict_wildcard(self) -> None:
        """Test wildcard to dict."""
        condition = MatchCondition(match_all=True)
        d = condition.to_dict()
        assert d == {"match": "*"}


# =============================================================================
# Test PolicyRule
# =============================================================================


class TestPolicyRule:
    """Tests for PolicyRule."""

    def test_create_rule(self) -> None:
        """Test creating a policy rule."""
        rule = PolicyRule(
            match=MatchCondition(vid="046d"),
            action=Action.ALLOW,
            comment="Test rule",
        )

        assert rule.action == Action.ALLOW
        assert rule.match.vid == "046d"

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        rule = PolicyRule(
            match=MatchCondition(vid="046d"),
            action=Action.BLOCK,
            comment="Block test",
        )
        d = rule.to_dict()

        assert d["action"] == "block"
        assert d["comment"] == "Block test"


# =============================================================================
# Test Policy Parser
# =============================================================================


class TestPolicyParser:
    """Tests for policy parsing."""

    def test_parse_simple_rule(self) -> None:
        """Test parsing a simple rule."""
        data = {
            "match": {"vid": "046d", "pid": "c534"},
            "action": "allow",
            "comment": "Logitech",
        }
        rule = parse_rule(data)

        assert rule.action == Action.ALLOW
        assert rule.match.vid == "046d"
        assert rule.comment == "Logitech"

    def test_parse_wildcard_rule(self) -> None:
        """Test parsing wildcard rule."""
        data = {"match": "*", "action": "review"}
        rule = parse_rule(data)

        assert rule.match.is_wildcard() is True
        assert rule.action == Action.REVIEW

    def test_parse_class_by_name(self) -> None:
        """Test parsing class by name."""
        data = {"match": {"class": "HID"}, "action": "review"}
        rule = parse_rule(data)

        assert rule.match.device_class == USBClass.HID

    def test_parse_class_by_hex(self) -> None:
        """Test parsing class by hex string."""
        data = {"match": {"class": "0x03"}, "action": "review"}
        rule = parse_rule(data)

        assert rule.match.device_class == 0x03

    def test_parse_policy_from_dict(self) -> None:
        """Test parsing full policy from dict."""
        data = {
            "rules": [
                {"match": {"vid": "046d"}, "action": "allow"},
                {"match": "*", "action": "review"},
            ]
        }
        policy = parse_policy(data)

        assert len(policy.rules) == 2
        assert policy.rules[0].action == Action.ALLOW

    def test_parse_invalid_action(self) -> None:
        """Test parsing invalid action raises error."""
        data = {"match": {"vid": "046d"}, "action": "invalid"}

        with pytest.raises(PolicyParseError, match="Invalid action"):
            parse_rule(data)

    def test_parse_missing_match(self) -> None:
        """Test parsing rule without match raises error."""
        data = {"action": "allow"}

        with pytest.raises(PolicyParseError, match="must have 'match'"):
            parse_rule(data)

    def test_parse_missing_action(self) -> None:
        """Test parsing rule without action raises error."""
        data = {"match": {"vid": "046d"}}

        with pytest.raises(PolicyParseError, match="must have 'action'"):
            parse_rule(data)

    def test_load_policy_from_file(self, temp_dir: Path) -> None:
        """Test loading policy from YAML file."""
        policy_content = textwrap.dedent("""
            rules:
              - match:
                  vid: '046d'
                  pid: 'c534'
                action: allow
                comment: 'Logitech'
              - match: '*'
                action: review
        """)
        policy_file = temp_dir / "test_policy.yaml"
        policy_file.write_text(policy_content)

        policy = load_policy(policy_file)

        assert len(policy.rules) == 2
        assert policy.rules[0].match.vid == "046d"

    def test_load_policy_file_not_found(self, temp_dir: Path) -> None:
        """Test loading non-existent policy file."""
        with pytest.raises(FileNotFoundError):
            load_policy(temp_dir / "nonexistent.yaml")


# =============================================================================
# Test Policy Validation
# =============================================================================


class TestPolicyValidation:
    """Tests for policy validation."""

    def test_validate_empty_policy(self) -> None:
        """Test validation of empty policy."""
        policy = Policy(rules=[])
        errors = validate_policy(policy)

        assert any("no rules" in e.lower() for e in errors)

    def test_validate_duplicate_vid_pid(self) -> None:
        """Test validation detects duplicate VID:PID."""
        policy = Policy(rules=[
            PolicyRule(MatchCondition(vid="046d", pid="c534"), Action.ALLOW),
            PolicyRule(MatchCondition(vid="046d", pid="c534"), Action.BLOCK),
        ])
        errors = validate_policy(policy)

        assert any("same VID:PID" in e for e in errors)

    def test_validate_invalid_regex(self) -> None:
        """Test validation detects invalid regex."""
        policy = Policy(rules=[
            PolicyRule(
                MatchCondition(manufacturer="[invalid(regex"),
                Action.REVIEW,
            ),
        ])
        errors = validate_policy(policy)

        assert any("Invalid regex" in e for e in errors)

    def test_validate_unreachable_rules(self) -> None:
        """Test validation detects unreachable rules."""
        policy = Policy(rules=[
            PolicyRule(MatchCondition(match_all=True), Action.REVIEW),
            PolicyRule(MatchCondition(vid="046d"), Action.ALLOW),  # Unreachable
        ])
        errors = validate_policy(policy)

        assert any("unreachable" in e.lower() for e in errors)

    def test_validate_valid_policy(self, sample_policy: Policy) -> None:
        """Test validation passes for valid policy."""
        errors = validate_policy(sample_policy)
        # May have warnings but no errors
        assert not any("Error" in e for e in errors)


# =============================================================================
# Test RuleMatcher
# =============================================================================


class TestRuleMatcher:
    """Tests for RuleMatcher."""

    def test_match_vid_pid(self, sample_device: DeviceDescriptor) -> None:
        """Test matching by VID:PID."""
        matcher = RuleMatcher()
        condition = MatchCondition(vid="046d", pid="c534")

        assert matcher.matches(condition, sample_device) is True

    def test_match_vid_only(self, sample_device: DeviceDescriptor) -> None:
        """Test matching by VID only."""
        matcher = RuleMatcher()
        condition = MatchCondition(vid="046d")

        assert matcher.matches(condition, sample_device) is True

    def test_no_match_wrong_vid(self, sample_device: DeviceDescriptor) -> None:
        """Test no match with wrong VID."""
        matcher = RuleMatcher()
        condition = MatchCondition(vid="1234")

        assert matcher.matches(condition, sample_device) is False

    def test_match_wildcard(self, sample_device: DeviceDescriptor) -> None:
        """Test wildcard matches everything."""
        matcher = RuleMatcher()
        condition = MatchCondition(match_all=True)

        assert matcher.matches(condition, sample_device) is True

    def test_match_device_class(self, sample_device: DeviceDescriptor) -> None:
        """Test matching by device class."""
        matcher = RuleMatcher()
        condition = MatchCondition(device_class=0x03)  # HID

        assert matcher.matches(condition, sample_device) is True

    def test_match_manufacturer_regex(self, sample_device: DeviceDescriptor) -> None:
        """Test matching manufacturer with regex."""
        matcher = RuleMatcher()
        condition = MatchCondition(manufacturer="(?i)logi.*")

        assert matcher.matches(condition, sample_device) is True

    def test_match_has_hid(self, sample_device: DeviceDescriptor) -> None:
        """Test matching has_hid_endpoint."""
        matcher = RuleMatcher()
        condition = MatchCondition(has_hid_endpoint=True)

        assert matcher.matches(condition, sample_device) is True

    def test_match_has_storage(self, attack_device: DeviceDescriptor) -> None:
        """Test matching has_storage_endpoint."""
        matcher = RuleMatcher()
        condition = MatchCondition(has_storage_endpoint=True)

        assert matcher.matches(condition, attack_device) is True

    def test_match_first_seen(self, sample_device: DeviceDescriptor) -> None:
        """Test matching first_seen."""
        db = FingerprintDatabase()
        matcher = RuleMatcher(fingerprint_db=db)
        condition = MatchCondition(first_seen=True)

        # First time - should match
        assert matcher.matches(condition, sample_device) is True

    def test_case_insensitive_vid(self, sample_device: DeviceDescriptor) -> None:
        """Test VID matching is case-insensitive."""
        matcher = RuleMatcher()
        condition = MatchCondition(vid="046D")  # Uppercase

        assert matcher.matches(condition, sample_device) is True


# =============================================================================
# Test PolicyEngine
# =============================================================================


class TestPolicyEngine:
    """Tests for PolicyEngine."""

    def test_evaluate_allow(
        self,
        policy_engine: PolicyEngine,
        sample_device: DeviceDescriptor,
    ) -> None:
        """Test evaluation returns ALLOW."""
        result = policy_engine.evaluate(sample_device)

        assert result.action == Action.ALLOW
        assert result.matched_rule is not None
        assert "Logitech" in result.reason

    def test_evaluate_block(
        self,
        policy_engine: PolicyEngine,
        attack_device: DeviceDescriptor,
    ) -> None:
        """Test evaluation returns BLOCK."""
        result = policy_engine.evaluate(attack_device)

        assert result.action == Action.BLOCK
        assert "CH340" in result.reason

    def test_evaluate_review_default(self, policy_engine: PolicyEngine) -> None:
        """Test evaluation returns REVIEW for unknown device."""
        unknown = create_test_descriptor(
            vid="9999",
            pid="9999",
            manufacturer="Unknown",
            product="Unknown Device",
        )
        result = policy_engine.evaluate(unknown)

        assert result.action == Action.REVIEW

    def test_evaluate_result_properties(
        self,
        policy_engine: PolicyEngine,
        sample_device: DeviceDescriptor,
    ) -> None:
        """Test EvaluationResult properties."""
        result = policy_engine.evaluate(sample_device)

        assert result.should_allow is True
        assert result.should_block is False
        assert result.needs_review is False

    def test_evaluate_timing(
        self,
        policy_engine: PolicyEngine,
        sample_device: DeviceDescriptor,
    ) -> None:
        """Test evaluation timing is recorded."""
        result = policy_engine.evaluate(sample_device)

        assert result.evaluation_time_ms >= 0

    def test_statistics(
        self,
        policy_engine: PolicyEngine,
        sample_device: DeviceDescriptor,
        attack_device: DeviceDescriptor,
    ) -> None:
        """Test statistics tracking."""
        policy_engine.evaluate(sample_device)  # Allow
        policy_engine.evaluate(attack_device)  # Block

        stats = policy_engine.get_statistics()

        assert stats["total_evaluations"] == 2
        assert stats["allowed"] == 1
        assert stats["blocked"] == 1

    def test_check_device_quick(self, policy_engine: PolicyEngine) -> None:
        """Test quick VID:PID check."""
        # Known device
        result = policy_engine.check_device_quick("046d", "c534")
        assert result == Action.ALLOW

        # Unknown device
        result = policy_engine.check_device_quick("9999", "9999")
        assert result is None

    def test_from_file(self, temp_dir: Path) -> None:
        """Test creating engine from file."""
        policy_content = textwrap.dedent("""
            rules:
              - match:
                  vid: '046d'
                action: allow
        """)
        policy_file = temp_dir / "engine_policy.yaml"
        policy_file.write_text(policy_content)

        engine = PolicyEngine.from_file(policy_file)

        assert len(engine.policy.rules) == 1

    def test_reload_policy(self, temp_dir: Path) -> None:
        """Test reloading policy."""
        # Initial policy
        policy_file = temp_dir / "reload_policy.yaml"
        policy_file.write_text("rules:\n  - match: '*'\n    action: review")

        engine = PolicyEngine.from_file(policy_file)
        assert len(engine.policy.rules) == 1

        # Update policy
        policy_file.write_text(textwrap.dedent("""
            rules:
              - match:
                  vid: '046d'
                action: allow
              - match: '*'
                action: block
        """))

        errors = engine.reload_policy(policy_file)

        assert len(engine.policy.rules) == 2


# =============================================================================
# Test PolicyBuilder
# =============================================================================


class TestPolicyBuilder:
    """Tests for PolicyBuilder."""

    def test_build_simple_policy(self) -> None:
        """Test building a simple policy."""
        policy = (
            PolicyBuilder()
            .allow("046d", comment="Logitech")
            .block("1a86", "7523", comment="CH340")
            .default_review()
            .build()
        )

        assert len(policy.rules) == 3
        assert policy.rules[0].action == Action.ALLOW
        assert policy.rules[1].action == Action.BLOCK
        assert policy.rules[2].match.is_wildcard()

    def test_build_class_rules(self) -> None:
        """Test building class-based rules."""
        policy = (
            PolicyBuilder()
            .allow_class("Audio")
            .block_class("Mass Storage")
            .build()
        )

        assert len(policy.rules) == 2
        assert policy.rules[0].match.device_class == "Audio"

    def test_review_helpers(self) -> None:
        """Test review helper methods."""
        policy = (
            PolicyBuilder()
            .review_first_seen()
            .review_hid_with_storage()
            .build()
        )

        assert len(policy.rules) == 2
        assert policy.rules[0].match.first_seen is True
        assert policy.rules[1].match.has_storage_endpoint is True

    def test_build_engine(self) -> None:
        """Test building engine directly."""
        engine = (
            PolicyBuilder()
            .allow("046d")
            .default_review()
            .build_engine()
        )

        assert isinstance(engine, PolicyEngine)
        assert len(engine.policy.rules) == 2


# =============================================================================
# Test Default Policy
# =============================================================================


class TestDefaultPolicy:
    """Tests for default policy creation."""

    def test_create_default_policy(self) -> None:
        """Test creating default policy."""
        policy = create_default_policy()

        assert len(policy.rules) > 0
        # Should have trusted vendors
        assert any(r.match.vid == "046d" for r in policy.rules)
        # Should have blocked devices
        assert any(r.match.vid == "1a86" for r in policy.rules)
        # Should have default rule
        assert policy.rules[-1].match.is_wildcard()

    def test_default_policy_evaluation(self, sample_device: DeviceDescriptor) -> None:
        """Test evaluating with default policy."""
        policy = create_default_policy()
        engine = PolicyEngine(policy=policy)

        result = engine.evaluate(sample_device)

        # Logitech should be allowed
        assert result.action == Action.ALLOW
