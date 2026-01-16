"""
Risk scoring and analysis result handling.

Processes LLM analysis output and converts to actionable verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sentinel.policy.models import Action


class Verdict(Enum):
    """Analysis verdict from LLM."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANDBOX = "SANDBOX"

    def __str__(self) -> str:
        return self.value


@dataclass
class AnalysisResult:
    """Result from LLM analysis."""

    risk_score: int  # 0-100
    verdict: Verdict
    analysis: str  # Explanation from LLM
    confidence: float = 1.0  # 0-1, how confident the LLM is

    def __post_init__(self) -> None:
        # Validate risk score range
        if not 0 <= self.risk_score <= 100:
            raise ValueError(f"risk_score must be 0-100, got {self.risk_score}")
        # Validate confidence range
        if not 0 <= self.confidence <= 1:
            raise ValueError(f"confidence must be 0-1, got {self.confidence}")

    @classmethod
    def from_dict(cls, data: dict) -> AnalysisResult:
        """Create from dictionary (LLM response)."""
        return cls(
            risk_score=int(data["risk_score"]),
            verdict=Verdict(data["verdict"].upper()),
            analysis=data.get("analysis", ""),
            confidence=float(data.get("confidence", 1.0)),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "risk_score": self.risk_score,
            "verdict": str(self.verdict),
            "analysis": self.analysis,
            "confidence": self.confidence,
        }


def score_to_action(score: int) -> Action:
    """
    Convert risk score to policy action.

    Score ranges:
        0-25:   ALLOW (low risk)
        26-50:  ALLOW with monitoring
        51-75:  SANDBOX (needs inspection)
        76-100: BLOCK (high risk)

    Args:
        score: Risk score 0-100

    Returns:
        Corresponding Action
    """
    if score <= 50:
        return Action.ALLOW
    elif score <= 75:
        # SANDBOX maps to REVIEW for re-evaluation
        return Action.REVIEW
    else:
        return Action.BLOCK


def verdict_to_action(verdict: Verdict) -> Action:
    """
    Convert LLM verdict to policy action.

    Args:
        verdict: LLM verdict

    Returns:
        Corresponding Action
    """
    mapping = {
        Verdict.ALLOW: Action.ALLOW,
        Verdict.BLOCK: Action.BLOCK,
        Verdict.SANDBOX: Action.REVIEW,
    }
    return mapping[verdict]


def calculate_composite_score(
    base_score: int,
    confidence: float,
    first_seen: bool = False,
    has_anomalies: bool = False,
) -> int:
    """
    Calculate composite risk score with modifiers.

    Args:
        base_score: Initial risk score from analysis
        confidence: LLM confidence level (0-1)
        first_seen: Whether device was never seen before
        has_anomalies: Whether descriptor anomalies were detected

    Returns:
        Adjusted risk score (0-100)
    """
    score = base_score

    # Low confidence increases uncertainty (push toward review)
    if confidence < 0.7:
        # Move score toward middle (50) for uncertain results
        score = int(score * confidence + 50 * (1 - confidence))

    # First-seen devices get a penalty
    if first_seen:
        score = min(100, score + 15)

    # Anomalies increase risk
    if has_anomalies:
        score = min(100, score + 20)

    return max(0, min(100, score))


# Risk score thresholds
THRESHOLD_LOW = 25
THRESHOLD_MEDIUM = 50
THRESHOLD_HIGH = 75


def get_risk_level(score: int) -> str:
    """
    Get human-readable risk level from score.

    Args:
        score: Risk score 0-100

    Returns:
        Risk level string
    """
    if score <= THRESHOLD_LOW:
        return "LOW"
    elif score <= THRESHOLD_MEDIUM:
        return "MEDIUM"
    elif score <= THRESHOLD_HIGH:
        return "HIGH"
    else:
        return "CRITICAL"
