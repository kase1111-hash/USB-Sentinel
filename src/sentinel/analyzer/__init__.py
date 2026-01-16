"""
LLM Analyzer - Layer 3.

Provides heuristic threat assessment for devices using
LLM-powered analysis with constitutional bounds.
"""

from sentinel.analyzer.scoring import AnalysisResult, score_to_action

__all__ = [
    "AnalysisResult",
    "score_to_action",
]
