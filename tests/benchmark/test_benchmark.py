"""
Benchmark: what the daemon actually does with known-bad and known-good devices.

Every labeled descriptor goes through ``SentinelDaemon.evaluate()`` with the
shipped ``config/policy.yaml``: the same decision code that authorizes or
blocks real devices. A device counts as *stopped* when it is not authorized
(blocked, or held for manual review); a stopped benign device is a false
positive.

The LLM is not exercised here (it needs an API key). These numbers cover the
local validator + heuristics, which run with or without one; the LLM can
only add risk on top of them.

Baselines are the two ways a policy-only firewall can treat ``review``:

- review -> allow: fail open (what the daemon used to do)
- review -> hold: pure zero trust (every unknown device needs approval)

The analysis layer earns its place only if it beats both: catching what
fail-open lets through without holding what zero-trust holds.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.config import SentinelConfig
from sentinel.daemon import Decision, SentinelDaemon
from sentinel.policy.engine import PolicyEngine
from sentinel.policy.models import Action
from sentinel.policy.parser import load_policy
from tests.benchmark.descriptors import ALL_DESCRIPTORS, BENIGN, MALICIOUS, LabeledDescriptor

SHIPPED_POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.yaml"


@dataclass
class Outcome:
    """Which devices of each label were stopped (not authorized)."""

    malicious_stopped: list[str] = field(default_factory=list)
    malicious_allowed: list[str] = field(default_factory=list)
    benign_stopped: list[str] = field(default_factory=list)
    benign_allowed: list[str] = field(default_factory=list)

    def add(self, item: LabeledDescriptor, stopped: bool) -> None:
        bucket = {
            (True, True): self.malicious_stopped,
            (True, False): self.malicious_allowed,
            (False, True): self.benign_stopped,
            (False, False): self.benign_allowed,
        }[(item.is_malicious, stopped)]
        bucket.append(item.name)

    @property
    def recall(self) -> float:
        total = len(self.malicious_stopped) + len(self.malicious_allowed)
        return len(self.malicious_stopped) / total

    @property
    def false_positive_rate(self) -> float:
        total = len(self.benign_stopped) + len(self.benign_allowed)
        return len(self.benign_stopped) / total

    def summary(self) -> str:
        malicious = len(self.malicious_stopped) + len(self.malicious_allowed)
        benign = len(self.benign_stopped) + len(self.benign_allowed)
        return (
            f"  attacks stopped: {len(self.malicious_stopped)}/{malicious} ({self.recall:.0%})"
            f"   benign stopped: {len(self.benign_stopped)}/{benign}"
            f" ({self.false_positive_rate:.0%})"
        )


@pytest.fixture(scope="module")
def decisions(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Decision]:
    """Run the daemon's decision pipeline once over the whole dataset."""
    work = tmp_path_factory.mktemp("benchmark")
    config = SentinelConfig.from_dict(
        {
            "daemon": {"log_level": "warning", "log_file": None},
            "policy": {"rules_file": str(SHIPPED_POLICY)},
            "database": {"path": str(work / "audit.db")},
            "analyzer": {"enabled": False},
            "alerts": {"enabled": False},
        }
    )
    daemon = SentinelDaemon(config)
    daemon._interceptor = MagicMock()

    async def run() -> dict[str, Decision]:
        return {item.name: await daemon.evaluate(item.descriptor) for item in ALL_DESCRIPTORS}

    return asyncio.run(run())


@pytest.fixture(scope="module")
def pipeline(decisions: dict[str, Decision]) -> Outcome:
    outcome = Outcome()
    for item in ALL_DESCRIPTORS:
        outcome.add(item, decisions[item.name].action != Action.ALLOW)
    return outcome


def _policy_only(review_stops: bool) -> Outcome:
    engine = PolicyEngine(policy=load_policy(SHIPPED_POLICY))
    outcome = Outcome()
    for item in ALL_DESCRIPTORS:
        action = engine.evaluate(item.descriptor).action
        outcome.add(item, action == Action.BLOCK or (review_stops and action == Action.REVIEW))
    return outcome


class TestShippedPolicy:
    def test_known_attack_signatures_blocked_by_rule(self, decisions):
        for name in ("CH340 serial adapter", "STM32 DFU bootloader", "Bash Bunny"):
            assert decisions[name].action == Action.BLOCK, name
            assert decisions[name].reason.startswith("Policy:"), name

    def test_spoofed_vendor_not_covered_by_allow_rule(self, decisions):
        """A VID allow rule must not wave through a device lying about its vendor."""
        assert decisions["Vendor mismatch (fake Logitech VID)"].action != Action.ALLOW


class TestDetection:
    def test_attacks_stopped(self, pipeline):
        assert pipeline.recall >= 0.90, pipeline.malicious_allowed

    def test_benign_devices_allowed(self, pipeline):
        assert pipeline.false_positive_rate <= 0.10, pipeline.benign_stopped

    def test_no_benign_device_hard_blocked(self, decisions):
        """At worst a benign device is held, which one `devices trust` fixes."""
        blocked = [i.name for i in BENIGN if decisions[i.name].action == Action.BLOCK]
        assert blocked == []

    def test_analysis_beats_both_policy_only_baselines(self, pipeline):
        fail_open = _policy_only(review_stops=False)
        zero_trust = _policy_only(review_stops=True)

        assert pipeline.recall > fail_open.recall
        assert pipeline.false_positive_rate < zero_trust.false_positive_rate

    def test_report(self, decisions, pipeline):
        """Print the benchmark table (run with -s to see it)."""
        print("\n" + "=" * 72)
        print(f"USB Sentinel detection benchmark ({len(MALICIOUS)} attacks, {len(BENIGN)} benign)")
        print("=" * 72)
        print(f"policy only, review->allow\n{_policy_only(review_stops=False).summary()}")
        print(f"policy only, review->hold\n{_policy_only(review_stops=True).summary()}")
        print(f"daemon pipeline (local analysis)\n{pipeline.summary()}")
        print("-" * 72)
        for item in ALL_DESCRIPTORS:
            d = decisions[item.name]
            label = "ATTACK" if item.is_malicious else "benign"
            print(f"{label:<7}{d.action.value:<7}{item.name:<42}{d.reason[:60]}")
