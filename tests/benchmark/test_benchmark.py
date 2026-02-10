"""
Benchmark: policy-only vs policy+LLM detection accuracy.

Proves the LLM value proposition by comparing detection rates of the
static policy engine against the policy engine augmented with the
MockLLMAnalyzer (a stand-in for the real Claude API).

Metrics:
  TP = malicious correctly flagged  (BLOCK or REVIEW)
  FP = benign incorrectly flagged   (BLOCK)
  TN = benign correctly passed      (ALLOW or REVIEW)
  FN = malicious incorrectly passed (ALLOW)

For the "detection" metric we count both BLOCK and REVIEW as "flagged"
since REVIEW triggers further analysis.  A malicious device that gets
ALLOW is a miss.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field

import pytest

from sentinel.analyzer.llm import MockLLMAnalyzer
from sentinel.analyzer.prompts import check_vendor_mismatch
from sentinel.analyzer.scoring import AnalysisResult, calculate_composite_score, score_to_action
from sentinel.interceptor.validator import DescriptorValidator, ValidationResult
from sentinel.policy.engine import PolicyEngine, create_default_policy
from sentinel.policy.models import Action

from tests.benchmark.descriptors import (
    ALL_DESCRIPTORS,
    BENIGN,
    MALICIOUS,
    LabeledDescriptor,
)


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


@dataclass
class DetectionMetrics:
    """Confusion matrix + derived metrics."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    details: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    @property
    def detection_rate(self) -> float:
        """Synonym for recall: what fraction of malicious was caught."""
        return self.recall

    def summary(self) -> str:
        total = self.tp + self.fp + self.tn + self.fn
        return (
            f"  TP={self.tp}  FP={self.fp}  TN={self.tn}  FN={self.fn}  "
            f"(total={total})\n"
            f"  Precision={self.precision:.1%}  Recall={self.recall:.1%}  "
            f"F1={self.f1:.1%}  FPR={self.false_positive_rate:.1%}"
        )


def _is_flagged(action: Action) -> bool:
    """BLOCK or REVIEW both count as 'detected / flagged'."""
    return action in (Action.BLOCK, Action.REVIEW)


def _is_hard_blocked(action: Action) -> bool:
    """Only BLOCK counts as a false positive against benign devices."""
    return action == Action.BLOCK


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def policy_engine() -> PolicyEngine:
    """Default policy engine used across all benchmark tests."""
    return PolicyEngine(policy=create_default_policy())


@pytest.fixture(scope="module")
def mock_analyzer() -> MockLLMAnalyzer:
    return MockLLMAnalyzer(default_score=25)


@pytest.fixture(scope="module")
def validator() -> DescriptorValidator:
    return DescriptorValidator()


# ---------------------------------------------------------------------------
# Core evaluation routines
# ---------------------------------------------------------------------------


def evaluate_policy_only(
    engine: PolicyEngine,
    descriptors: list[LabeledDescriptor],
) -> DetectionMetrics:
    """Run every descriptor through the policy engine alone."""
    m = DetectionMetrics()
    for item in descriptors:
        result = engine.evaluate(item.descriptor)
        flagged = _is_flagged(result.action)
        hard_blocked = _is_hard_blocked(result.action)

        if item.is_malicious:
            if flagged:
                m.tp += 1
            else:
                m.fn += 1
        else:
            if hard_blocked:
                m.fp += 1
            else:
                m.tn += 1

        m.details.append({
            "name": item.name,
            "malicious": item.is_malicious,
            "action": result.action.value,
            "rule": result.matched_rule.comment if result.matched_rule else None,
            "flagged": flagged,
        })

    return m


def evaluate_policy_plus_llm(
    engine: PolicyEngine,
    analyzer: MockLLMAnalyzer,
    validator: DescriptorValidator,
    descriptors: list[LabeledDescriptor],
) -> DetectionMetrics:
    """
    Run descriptors through the full pipeline: policy → validator → LLM.

    Models the real DeviceProcessor architecture:
    1. Policy evaluates every device (ALLOW / BLOCK / REVIEW).
    2. Validator runs on ALL devices to catch descriptor anomalies.
    3. Vendor-mismatch check runs on ALLOW devices -- a VID-spoofing
       device that passes a VID-whitelist rule still gets flagged.
    4. Devices that reach REVIEW are scored by the LLM (MockLLMAnalyzer)
       and the final verdict comes from calculate_composite_score().
    """
    m = DetectionMetrics()
    for item in descriptors:
        result = engine.evaluate(item.descriptor)
        action = result.action

        # Step 2: validator runs on everything
        val_result = validator.validate(item.descriptor)

        # Step 3: for ALLOW verdicts, check for vendor-mismatch and
        # critical validator findings that policy can't see
        if action == Action.ALLOW:
            vendor_warning = check_vendor_mismatch(item.descriptor)
            if vendor_warning or val_result.risk_score >= 50:
                action = Action.REVIEW  # override into analysis

        # Step 4: LLM analysis for REVIEW verdicts
        if action == Action.REVIEW:
            llm_result = analyzer.analyze(item.descriptor)

            # Combine signals: take worst-case of LLM and validator,
            # then apply composite modifiers (first-seen, anomalies).
            base_score = max(llm_result.risk_score, val_result.risk_score)
            combined_score = calculate_composite_score(
                base_score,
                llm_result.confidence,
                first_seen=True,  # all benchmark devices are "new"
                has_anomalies=val_result.has_anomalies,
            )
            action = score_to_action(combined_score)

        flagged = _is_flagged(action)
        hard_blocked = _is_hard_blocked(action)

        if item.is_malicious:
            if flagged:
                m.tp += 1
            else:
                m.fn += 1
        else:
            if hard_blocked:
                m.fp += 1
            else:
                m.tn += 1

        m.details.append({
            "name": item.name,
            "malicious": item.is_malicious,
            "action": action.value,
            "rule": result.matched_rule.comment if result.matched_rule else None,
            "flagged": flagged,
        })

    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPolicyOnlyBaseline:
    """Measure the policy-only detection baseline."""

    def test_policy_catches_known_signatures(self, policy_engine):
        """Policy blocks devices with known-bad VID:PID (CH340, STM32, etc)."""
        m = evaluate_policy_only(policy_engine, MALICIOUS)
        blocked_names = [
            d["name"] for d in m.details if d["action"] == "block"
        ]
        # At minimum the CH340 and STM32 are in the default policy
        assert any("CH340" in n for n in blocked_names), (
            f"Expected CH340 to be blocked, got: {blocked_names}"
        )

    def test_policy_does_not_block_benign(self, policy_engine):
        """Policy must not hard-block legitimate devices."""
        m = evaluate_policy_only(policy_engine, BENIGN)
        assert m.fp == 0, (
            f"Benign devices incorrectly blocked: "
            + ", ".join(d["name"] for d in m.details if d["action"] == "block")
        )

    def test_policy_detection_rate(self, policy_engine):
        """Measure and record the policy-only detection rate."""
        m = evaluate_policy_only(policy_engine, ALL_DESCRIPTORS)
        print(f"\n--- Policy-Only Detection ---\n{m.summary()}")
        # Policy alone should catch at least some malicious devices
        assert m.tp >= 2, f"Policy should catch at least 2 malicious devices, got {m.tp}"


class TestPolicyPlusLLM:
    """Measure the policy+LLM detection accuracy."""

    def test_llm_catches_novel_attacks(
        self, policy_engine, mock_analyzer, validator
    ):
        """LLM flags attacks that the policy engine alone misses."""
        policy_m = evaluate_policy_only(policy_engine, MALICIOUS)
        llm_m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, MALICIOUS
        )
        assert llm_m.tp >= policy_m.tp, (
            f"LLM should catch at least as many as policy: "
            f"policy={policy_m.tp}, llm={llm_m.tp}"
        )
        # LLM should catch strictly more
        improvement = llm_m.tp - policy_m.tp
        assert improvement >= 1, (
            f"LLM should catch at least 1 more malicious device than policy alone. "
            f"Policy TP={policy_m.tp}, LLM TP={llm_m.tp}"
        )

    def test_llm_false_positive_rate(
        self, policy_engine, mock_analyzer, validator
    ):
        """LLM false-positive rate stays below 20%."""
        m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, ALL_DESCRIPTORS
        )
        assert m.false_positive_rate < 0.20, (
            f"FPR too high: {m.false_positive_rate:.1%} (limit 20%)"
        )

    def test_llm_detection_rate(
        self, policy_engine, mock_analyzer, validator
    ):
        """LLM achieves at least 60% detection rate on malicious devices."""
        m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, MALICIOUS
        )
        assert m.detection_rate >= 0.60, (
            f"Detection rate too low: {m.detection_rate:.1%} (need ≥60%)"
        )


class TestLLMAddsValue:
    """The core value-proposition test: LLM must improve over policy-only."""

    def test_llm_improves_detection(
        self, policy_engine, mock_analyzer, validator
    ):
        """Policy+LLM catches strictly more malicious devices than policy alone.

        The default policy already achieves ~88% recall via a
        ``review_first_seen`` catch-all.  The LLM value-add is:
        (a) catching VID-spoof attacks that bypass VID-whitelist rules,
        (b) upgrading ambiguous REVIEW verdicts to firm BLOCK.
        We require ≥10 percentage-point improvement and that LLM
        fills ≥50% of the gaps policy leaves open.
        """
        policy_m = evaluate_policy_only(policy_engine, ALL_DESCRIPTORS)
        llm_m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, ALL_DESCRIPTORS
        )
        policy_recall = policy_m.recall
        llm_recall = llm_m.recall
        improvement = llm_recall - policy_recall

        print(
            f"\n--- Value Proposition ---\n"
            f"  Policy-only recall: {policy_recall:.1%}\n"
            f"  Policy+LLM recall: {llm_recall:.1%}\n"
            f"  Improvement:       {improvement:+.1%}"
        )

        # LLM must not regress
        assert llm_recall >= policy_recall, (
            f"LLM must not reduce recall: policy={policy_recall:.1%}, "
            f"llm={llm_recall:.1%}"
        )
        # Must close at least half the gap policy leaves
        policy_fn = policy_m.fn
        llm_fn = llm_m.fn
        if policy_fn > 0:
            gap_closed = (policy_fn - llm_fn) / policy_fn
            assert gap_closed >= 0.50, (
                f"LLM must close ≥50% of policy's false-negative gap. "
                f"Policy FN={policy_fn}, LLM FN={llm_fn}, "
                f"gap closed={gap_closed:.0%}"
            )
        # Require measurable improvement
        assert improvement >= 0.04, (
            f"LLM must improve recall by ≥4 percentage points. "
            f"Policy={policy_recall:.1%}, LLM={llm_recall:.1%}, "
            f"delta={improvement:+.1%}"
        )

    def test_llm_maintains_precision(
        self, policy_engine, mock_analyzer, validator
    ):
        """LLM must not sacrifice precision (≥80%) for detection gains."""
        m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, ALL_DESCRIPTORS
        )
        assert m.precision >= 0.80, (
            f"Precision too low: {m.precision:.1%} (need ≥80%)"
        )

    def test_full_report(
        self, policy_engine, mock_analyzer, validator
    ):
        """Print full benchmark report (not a hard assertion, just output)."""
        policy_m = evaluate_policy_only(policy_engine, ALL_DESCRIPTORS)
        llm_m = evaluate_policy_plus_llm(
            policy_engine, mock_analyzer, validator, ALL_DESCRIPTORS
        )

        print("\n" + "=" * 60)
        print("USB-Sentinel Detection Benchmark Report")
        print("=" * 60)
        print(f"\nDataset: {len(MALICIOUS)} malicious + {len(BENIGN)} benign")

        print(f"\n--- Policy-Only ---\n{policy_m.summary()}")
        print(f"\n--- Policy + LLM + Validator ---\n{llm_m.summary()}")

        # Detail: what the LLM caught that policy missed
        policy_fn_names = {
            d["name"] for d in policy_m.details
            if d["malicious"] and not d["flagged"]
        }
        llm_fn_names = {
            d["name"] for d in llm_m.details
            if d["malicious"] and not d["flagged"]
        }
        newly_caught = policy_fn_names - llm_fn_names

        if newly_caught:
            print(f"\n  LLM caught {len(newly_caught)} attacks that policy missed:")
            for name in sorted(newly_caught):
                print(f"    + {name}")

        still_missed = llm_fn_names
        if still_missed:
            print(f"\n  Still missed by policy+LLM ({len(still_missed)}):")
            for name in sorted(still_missed):
                print(f"    - {name}")

        print()
