"""BankGuard AI - Static Reference Data (database/reference_data.py)
==================================================================
Static dictionaries and verified reference datasets for banking domains and helplines.

NOTE: BankGuard AI adheres to a strict Zero-User-Data retention policy.
No user messages, credentials, or session history are ever stored in any database.
This module stores purely static verification benchmarks and institutional registries.
"""

from __future__ import annotations

# Official verified banking domains in India (used to prevent lookalike false positives)
OFFICIAL_BANK_DOMAINS: tuple[str, ...] = (
    "sbi.co.in",
    "onlinesbi.sbi",
    "onlinesbi.com",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "pnbindia.in",
    "paytm.com",
    "bankofbaroda.in",
    "kotak.com",
    "canarabank.com",
    "rbi.org.in",
    "npci.org.in",
    "cybercrime.gov.in",
)

# Verified National Cybercrime Infrastructure (India Context)
CYBERCRIME_RESOURCES: dict[str, str] = {
    "helpline": "1930",
    "portal_url": "https://cybercrime.gov.in",
    "agency": "Citizen Financial Cyber Fraud Reporting and Management System (MHA, GoI)",
    "golden_hour_advice": "Report financial cyber fraud within the first 1-2 hours to increase fund recovery chances.",
}

