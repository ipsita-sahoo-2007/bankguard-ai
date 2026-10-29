"""BankGuard AI - Root Samples Proxy
==================================
Re-exports fictional sample messages from database.samples for backwards compatibility.
"""

from database.samples import SAMPLE_MESSAGES

__all__ = ["SAMPLE_MESSAGES"]
