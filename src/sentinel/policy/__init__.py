"""
Policy Engine - Layer 2.

Implements deterministic, rule-based device authorization.
Evaluates device attributes against a configured ruleset.
"""

from sentinel.policy.fingerprint import (
    DeviceFingerprint,
    FingerprintDatabase,
    FingerprintGenerator,
    fingerprint_match,
    generate_fingerprint,
)
from sentinel.policy.models import Action, MatchCondition, Policy, PolicyRule, USBClass
from sentinel.policy.parser import load_policy, parse_policy, validate_policy

__all__ = [
    # Fingerprinting
    "DeviceFingerprint",
    "FingerprintDatabase",
    "FingerprintGenerator",
    "fingerprint_match",
    "generate_fingerprint",
    # Models
    "Action",
    "MatchCondition",
    "Policy",
    "PolicyRule",
    "USBClass",
    # Parser
    "load_policy",
    "parse_policy",
    "validate_policy",
]
