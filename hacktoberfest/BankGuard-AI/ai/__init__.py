"""BankGuard AI - AI Integration Package
======================================
Prompt injection defense, sensitive PII redaction, Gemini/Gemma API calling,
hallucination filtering, and safety-floor merging.
"""

from .ai_client import (
    analyze,
    build_prompt,
    call_ai,
    merge_results,
    redact,
    validate_ai_output,
)

__all__ = [
    "analyze",
    "build_prompt",
    "call_ai",
    "merge_results",
    "redact",
    "validate_ai_output",
]

