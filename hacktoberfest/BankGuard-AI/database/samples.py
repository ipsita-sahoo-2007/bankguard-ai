"""BankGuard AI - Fictional Samples Repository (database/samples.py)
==================================================================
Static reference collection of FICTIONAL test messages representing
common Indian banking SMS formats.

All bank names, phone numbers, transaction IDs, and URLs are entirely fictitious.
"""

from __future__ import annotations

SAMPLE_MESSAGES: dict[str, dict[str, str]] = {
    "fake_kyc": {
        "title": "🚨 Fake KYC Alert",
        "description": "Urgent suspension threat with a shortened phishing link",
        "text": (
            "Dear Customer, Your SampleBank account KYC has expired. "
            "Your debit card and net banking will be blocked within 24 hours. "
            "Click immediately to update your KYC: https://bit.ly/sample-bank-kyc-update"
        ),
    },
    "otp_request": {
        "title": "🔑 OTP Request",
        "description": "Social engineering attempt to extract OTP under false pretenses",
        "text": (
            "ABC Bank Alert: A fund transfer of INR 45,000 is initiated from your account. "
            "If this was not done by you, share OTP 849201 with our customer care manager "
            "immediately on 9876543210 to stop the transaction."
        ),
    },
    "upi_scam": {
        "title": "💸 UPI Payment Scam",
        "description": "Scammer tricking victim to enter UPI PIN to receive cashback",
        "text": (
            "Congratulations! You have received a cashback reward of INR 2,500 on XYZ Pay. "
            "Enter your UPI PIN to receive money directly into your bank account. "
            "Scan this QR or approve collect request: https://tinyurl.com/xyz-cashback-claim"
        ),
    },
    "legitimate_bank": {
        "title": "✅ Legitimate Bank Alert",
        "description": "Authentic automated transaction alert with safety advisory",
        "text": (
            "SampleBank: INR 1,850.00 debited from A/C XX8492 on 29-Oct-26 at GroceryStore. "
            "Avl Bal: INR 34,210.50. Never share your OTP, PIN or CVV with anyone. "
            "If not done by you, report unauthorized transaction via the official SampleBank mobile app."
        ),
    },
}

