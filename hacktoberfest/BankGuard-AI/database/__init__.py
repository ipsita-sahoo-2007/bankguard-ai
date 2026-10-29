"""BankGuard AI - Database / Static Reference Layer
===================================================
Static reference data and sample messages.
Strict zero-user-retention architecture.
"""

from .reference_data import CYBERCRIME_RESOURCES, OFFICIAL_BANK_DOMAINS
from .samples import SAMPLE_MESSAGES

__all__ = [
    "CYBERCRIME_RESOURCES",
    "OFFICIAL_BANK_DOMAINS",
    "SAMPLE_MESSAGES",
]

