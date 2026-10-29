"""BankGuard AI - Root AI Client Proxy
====================================
Re-exports the AI pipeline from ai.ai_client for backwards compatibility.
"""

from ai.ai_client import (
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
