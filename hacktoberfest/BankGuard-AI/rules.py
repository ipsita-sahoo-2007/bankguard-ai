"""BankGuard AI - Root Rules Engine Proxy
=========================================
Re-exports the core deterministic rules engine from backend.rules
to maintain seamless backwards compatibility with existing scripts and test runners.
"""

from backend.rules import (
    AnalysisResult,
    analyze_with_rules,
    get_standard_next_steps,
    POSITIVE_SIGNALS,
    NEGATIVE_SIGNALS,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
)

__all__ = [
    "AnalysisResult",
    "analyze_with_rules",
    "get_standard_next_steps",
    "POSITIVE_SIGNALS",
    "NEGATIVE_SIGNALS",
    "SCORE_THRESHOLD_HIGH",
    "SCORE_THRESHOLD_MEDIUM",
]
