"""BankGuard AI - Backend Package
================================
Contains deterministic analysis logic, rules engine, and safety floor enforcement.
"""

from .rules import (
    AnalysisResult,
    analyze_with_rules,
    get_standard_next_steps,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
)

__all__ = [
    "AnalysisResult",
    "analyze_with_rules",
    "get_standard_next_steps",
    "SCORE_THRESHOLD_HIGH",
    "SCORE_THRESHOLD_MEDIUM",
]

