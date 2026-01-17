"""
LLM Analyzer - Layer 3.

Provides heuristic threat assessment for devices using
LLM-powered analysis with constitutional bounds.
"""

from sentinel.analyzer.llm import (
    LLMAnalyzer,
    MockLLMAnalyzer,
    RetryConfig,
    TokenBucket,
    create_analyzer,
)
from sentinel.analyzer.local import (
    HybridAnalyzer,
    LocalLLMAnalyzer,
    LocalLLMConfig,
    create_local_analyzer,
)
from sentinel.analyzer.prompts import (
    SYSTEM_PROMPT,
    build_history_context,
    check_vendor_mismatch,
    format_behavior_prompt,
    format_device_prompt,
    sanitize_device_strings,
    sanitize_input,
    validate_response,
)
from sentinel.analyzer.scoring import (
    AnalysisResult,
    Verdict,
    calculate_composite_score,
    get_risk_level,
    score_to_action,
    verdict_to_action,
)

__all__ = [
    # Main analyzers
    "LLMAnalyzer",
    "MockLLMAnalyzer",
    "LocalLLMAnalyzer",
    "HybridAnalyzer",
    # Factory functions
    "create_analyzer",
    "create_local_analyzer",
    # Configuration
    "RetryConfig",
    "TokenBucket",
    "LocalLLMConfig",
    # Prompts
    "SYSTEM_PROMPT",
    "format_device_prompt",
    "format_behavior_prompt",
    "sanitize_input",
    "sanitize_device_strings",
    "validate_response",
    "check_vendor_mismatch",
    "build_history_context",
    # Scoring
    "AnalysisResult",
    "Verdict",
    "score_to_action",
    "verdict_to_action",
    "calculate_composite_score",
    "get_risk_level",
]
