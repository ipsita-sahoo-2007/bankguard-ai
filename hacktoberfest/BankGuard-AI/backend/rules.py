"""BankGuard AI - Rule-Based Engine (rules.py)
==============================================
Pure functional analyzer for banking SMS, UPI requests, and KYC alerts.
No Streamlit imports; this module is fully decoupled and testable offline.

Design:
- Weighted signal evaluation (positive signals increase score, negative signals decrease score)
- Distinguishes authentic security warnings (e.g., "never share your OTP") from scam requests
- Safety floor enforcement (hard constraints that prevent dangerous under-classification)
- Exact-substring phrase extraction from the original message
- Mandatory Indian cybercrime guidance (Helpline 1930 & cybercrime.gov.in)
"""

from __future__ import annotations

import re
from typing import Pattern, TypedDict


# ==============================================================================
# CONFIGURABLE THRESHOLDS & WEIGHTS
# Teammates: You can tune these weights and thresholds without breaking callers.
# ==============================================================================

SCORE_THRESHOLD_MEDIUM = 25
SCORE_THRESHOLD_HIGH = 60
MAX_SCORE = 100

# Signal categories (used by the safety floors instead of fragile description matching)
CAT_CREDENTIALS = "credentials"
CAT_UPI = "upi"
CAT_URGENCY = "urgency"
CAT_THREAT = "threat"
CAT_KYC = "kyc"
CAT_LINK = "link"
CAT_APP = "app"
CAT_REMOTE = "remote"
CAT_BAIT = "bait"
CAT_CONTACT = "contact"
CAT_TONE = "tone"

CAT_SAFETY_ADVICE = "safety_advice"
CAT_LEDGER = "ledger"
CAT_GRIEVANCE = "grievance"
CAT_OFFICIAL_CHANNEL = "official_channel"

# --- Building blocks -----------------------------------------------------------
_CRED_WORD = r"(?:otp|one[- ]time\s+password|pin|cvv|password|mpin|card\s+(?:number|details))"
_LIST_SEP = r"(?:\s*,\s*(?:or|and)\s+|\s*[,/&]\s*|\s+(?:or|and)\s+)"
_CRED_LIST = rf"{_CRED_WORD}(?:{_LIST_SEP}{_CRED_WORD})*\b"

# Not preceded by "never", "not", "don't", "doesn't", ... (straight or curly apostrophe)
_NOT_NEGATED = r"(?<!never\s)(?<!not\s)(?<!n['’]t\s)"

# Pattern identifying authentic bank security warnings (to prevent false triggers).
# It matches ONLY the warning clause itself, so a scam that hides in the same
# sentence ("Never share OTP, click http://bit.ly/x") is still scanned.
SAFETY_ADVICE_PATTERN = (
    r"\b(?:never|(?:do|must|should)\s+not|don['’]?t)\s+(?:ever\s+)?"
    rf"(?:share|disclose|tell|give|reveal|provide)\s+(?:(?:your|this|the|these|any)\s+)?{_CRED_LIST}"
    r"(?:\s+(?:with|to)\s+(?:anyone|anybody|any\s*one|others|a\s+third\s+party|strangers?))?"
    r"|"
    r"\b(?:banks?|we|officials?|employees?|staff)\s+(?:will\s+)?never\s+(?:calls?|asks?|requests?)"
    rf"(?:\s+(?:you\s+)?for\s+(?:(?:your|this|the)\s+)?{_CRED_LIST})?"
)

# Official domains that must not be flagged as "lookalike" (extend as needed)
OFFICIAL_BANK_DOMAINS = (
    r"sbi\.co\.in",
    r"onlinesbi\.(?:sbi|com)",
    r"hdfcbank\.com",
    r"icicibank\.com",
    r"axisbank\.com",
    r"pnbindia\.in",
    r"paytm\.com",
    r"bankofbaroda\.in",
    r"kotak\.com",
    r"canarabank\.com",
    r"rbi\.org\.in",
    r"npci\.org\.in",
    r"cybercrime\.gov\.in",
)
_OFFICIAL = "|".join(OFFICIAL_BANK_DOMAINS)
_TLDS = r"(?:com|in|org|net|xyz|top|live|online|vip|work|site|buzz|cc|co|info|click|link|icu|app)"

_LOOKALIKE_URL = (
    rf"https?://(?!(?:[a-z0-9\-]+\.)*(?:{_OFFICIAL})(?:[/:?#\s]|$))"
    r"(?:[a-z0-9\-]+\.)*[a-z0-9\-]*(?:sbi|hdfc|icici|axis|pnb|paytm|bank|kyc)[a-z0-9\-]*"
    rf"(?:\.[a-z0-9\-]+)*\.{_TLDS}\b(?:[/:?#]\S*)?"
)

# --- POSITIVE SIGNALS (SCAM / PHISHING / FRAUD PATTERNS) ---
# Each entry is: (regex_pattern, weight, warning_description, category)
POSITIVE_SIGNALS: list[tuple[str, int, str, str]] = [
    # 1. Credential harvesting (explicitly asking the victim to share or send)
    (
        rf"{_NOT_NEGATED}\b(?:share|send|provide|give|tell|forward|text)\s+(?:(?:me|us)\s+)?(?:(?:your|the|this)\s+)?{_CRED_LIST}",
        45,
        "Requests sensitive credentials (OTP, PIN, CVV, or passwords) which banks never ask you to share.",
        CAT_CREDENTIALS,
    ),
    (
        rf"{_NOT_NEGATED}\b(?:asks?|asking)\s+for\s+(?:(?:the|your)\s+)?{_CRED_LIST}",
        45,
        "Prompts the recipient to disclose or forward confidential verification credentials.",
        CAT_CREDENTIALS,
    ),
    (
        r"\b(?:verify|enter|update|confirm|submit)\s+(?:your\s+)?(?:password|credentials?|login\s+details|pin|mpin|card\s+number)\b",
        30,
        "Prompts verifying or updating sensitive passwords or login credentials.",
        CAT_CREDENTIALS,
    ),

    # 2. UPI scams (receiving money never requires entering a PIN or scanning a QR)
    (
        r"\b(?:enter|put|type|input)\s+(?:your\s+)?(?:upi\s+)?pin\s+to\s+(?:receive|accept|claim|get)\s+(?:the\s+)?(?:money|cash|amount|payment|refund)",
        45,
        "Instructs entering UPI PIN to receive money. In UPI architecture, entering PIN only debits money.",
        CAT_UPI,
    ),
    (
        r"\bscan\s+(?:this\s+|the\s+)?qr(?:\s*code)?\s+to\s+(?:receive|claim|accept|get)\s+(?:the\s+|your\s+)?(?:money|cash|payment|refund)",
        40,
        "Asks to scan a QR code to receive money (UPI). Scanning a QR code only authorizes outgoing payments.",
        CAT_UPI,
    ),
    (
        r"\b(?:upi\s+collect\s+request|approve\s+(?:the\s+|this\s+)?collect\s+request|request(?:s|ed)?\s+money\s+from\s+you)\b",
        30,
        "Unexpected UPI collect request, frequently used by scammers to drain linked accounts.",
        CAT_UPI,
    ),

    # 3. Urgency and threats (coercion psychology)
    (
        r"\b(?:within\s+(?:24|12|48|6|2|1)\s*(?:hours?|hrs?|ghontay)\b|immediately|urgently|last\s+(?:day|chance|warning)|today\s+only|expires?\s+(?:today|soon|tonight))",
        25,
        "High-urgency deadline designed to cause panic and bypass careful thinking.",
        CAT_URGENCY,
    ),
    (
        r"\b(?:account|a/c|debit\s+card|credit\s+card|atm\s+card|pan(?:\s+card)?|sim|upi\s+id|services?)\s+"
        r"(?:(?:will|shall|may)\s+be\s+|is\s+|has\s+been\s+|gets?\s+)?(?:temporarily\s+|permanently\s+)?"
        r"(?:blocked|suspended|deactivated|closed|frozen|terminated)\b",
        30,
        "Threatens sudden account, card, SIM, or service suspension to force rash action.",
        CAT_THREAT,
    ),
    (
        r"\b(?:kyc\s+(?:is\s+|has\s+)?(?:expired|pending|incomplete|suspended|unverified|update\s+required)|update\s+(?:your\s+)?kyc)\b",
        30,
        "Fake KYC expiration or pending update alert, a widespread bank-impersonation tactic.",
        CAT_KYC,
    ),
    (
        r"\b(?:electricity\s+(?:power\s+)?(?:will\s+be\s+)?(?:disconnected|cut)|bill\s+unpaid\s+power\s+cut)\b",
        30,
        "Utility disconnection threat prompting immediate contact with fraudulent numbers.",
        CAT_THREAT,
    ),

    # 4. Insecure, shortened, or lookalike links
    (
        r"https?://(?:www\.)?(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|cutt\.ly|rb\.gy|shorturl\.at|buff\.ly|ow\.ly)/[a-zA-Z0-9_\-]+",
        30,
        "Uses a shortened URL hiding the true destination web address.",
        CAT_LINK,
    ),
    (
        r"\bhttp://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s]*)?",
        25,
        "Insecure HTTP link instead of encrypted HTTPS, typical of disposable phishing sites.",
        CAT_LINK,
    ),
    (
        r"\bhttps?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?",
        35,
        "Direct IP-address link used to circumvent domain reputation and security blocklists.",
        CAT_LINK,
    ),
    (
        _LOOKALIKE_URL,
        35,
        "Suspicious lookalike domain attempting to impersonate legitimate banking infrastructure.",
        CAT_LINK,
    ),
    (
        r"\b(?:click|tap|visit|open)\s+(?:here|link|url|the\s+link)\s*[:\-]?\s*https?://",
        20,
        "Direct link embedded alongside an instruction to click or verify.",
        CAT_LINK,
    ),

    # 5. Dangerous software / remote access apps
    (
        r"(?:\.apk\b|\bdownload\s+(?:the\s+)?(?:app|apk|file)\b|\binstall\s+(?:the\s+)?(?:app|apk)\b)",
        35,
        "Prompts downloading an unverified APK or third-party application outside official app stores.",
        CAT_APP,
    ),
    (
        r"\b(?:anydesk|teamviewer|quick\s?support|rustdesk|screen\s*share|airdroid)\b",
        40,
        "Directs installation of remote-access software that allows scammers to view and control your screen.",
        CAT_REMOTE,
    ),

    # 6. Bait & Unofficial contact routes
    (
        r"\b(?:congratulations|won\s+(?:a\s+)?(?:lottery|prize|reward|gift|car)|lucky\s+draw|cashback\s+credited)\b",
        25,
        "Unrealistic reward, lottery, or cashback bait used to attract and deceive victims.",
        CAT_BAIT,
    ),
    (
        r"\b(?:call|whatsapp|contact|sampark\s*karein|jogajog\s*korun)\s+(?:customer\s*care|support|manager|helpdesk)?\s*(?:at|on|number)?\s*[:\-]?\s*"
        r"(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)",
        25,
        "Unofficial mobile number provided as bank or customer support helpline.",
        CAT_CONTACT,
    ),

    # 7. Hinglish / Regional urgency phrases (Hindi/Bengali in English letters)
    (
        r"\b(?:turant|abhi\s+update\s+karein|block\s+ho\s+jayega|band\s+ho\s+jayega|sampark\s+karein|khaata\s+band)\b",
        25,
        "Hinglish urgency phrasing commonly used in regional targeted SMS fraud.",
        CAT_URGENCY,
    ),
    (
        r"\b(?:bondho\s+hoye\s+jabe|shob\s+bondho|jogajog\s+korun|taka\s+ferot)\b",
        25,
        "Regional dialect urgency phrasing indicating informal, unsolicited communication.",
        CAT_URGENCY,
    ),

    # 8. Profile warnings and generic impersonation tone
    (
        r"\b(?:unverified\s+(?:email|profile|phone)|review\s+your\s+profile|pre-approved\s+personal\s+loan)\b",
        15,
        "Unsolicited profile review or unverified data claim typical of social engineering bait.",
        CAT_TONE,
    ),
    (
        r"\b(?:dear\s+customer|dear\s+user|dear\s+sir/madam|dear\s+consumer)\b",
        10,
        "Generic impersonal greeting without personalized customer identification.",
        CAT_TONE,
    ),
]


# --- NEGATIVE SIGNALS (LEGITIMATE BANK NOTIFICATION INDICATORS) ---
# Each entry is: (regex_pattern, weight, note, category)
NEGATIVE_SIGNALS: list[tuple[str, int, str, str]] = [
    (
        SAFETY_ADVICE_PATTERN,
        35,
        "Explicitly warns never to share OTP, PIN, or CVV, standard practice in genuine bank alerts.",
        CAT_SAFETY_ADVICE,
    ),
    (
        r"(?:debited\s+(?:by|from)|credited\s+(?:with|to)|deposited\s+with|txn\s+(?:of|id|with)|spent\s+on\s+card|avl\s+bal(?:ance)?\s*[:\-]?\s*(?:inr|rs)|term\s+deposit|fixed\s+deposit)",
        25,
        "Matches standard automated transaction ledger notification syntax.",
        CAT_LEDGER,
    ),
    (
        r"(?:if\s+not\s+(?:done|authorized|you)|report\s+unauthorized\s+transaction|block\s+card\s+via\s+official\s+app)",
        20,
        "Provides official grievance reporting guidance for unauthorized card/account transactions.",
        CAT_GRIEVANCE,
    ),
    (
        r"(?:use\s+official\s+(?:netbanking|bank\s+app)|call\s+number\s+on\s+(?:the\s+)?back\s+of\s+your\s+card)",
        15,
        "Guides customer to verified official banking channels rather than third-party links.",
        CAT_OFFICIAL_CHANNEL,
    ),
]

# Compile once at import time
_POSITIVE_COMPILED: list[tuple[Pattern[str], int, str, str]] = [
    (re.compile(p, re.IGNORECASE), w, d, c) for p, w, d, c in POSITIVE_SIGNALS
]
_NEGATIVE_COMPILED: list[tuple[Pattern[str], int, str, str]] = [
    (re.compile(p, re.IGNORECASE), w, d, c) for p, w, d, c in NEGATIVE_SIGNALS
]
_SAFETY_COMPILED = re.compile(SAFETY_ADVICE_PATTERN, re.IGNORECASE)
_KYC_WORD = re.compile(r"\bkyc\b", re.IGNORECASE)

_LINK_OR_APP_CATS = {CAT_LINK, CAT_APP, CAT_REMOTE}
_URGENCY_OR_THREAT_CATS = {CAT_URGENCY, CAT_THREAT, CAT_KYC}


class AnalysisResult(TypedDict):
    risk_level: str
    score: int
    warning_signs: list[str]
    suspicious_phrases: list[str]
    explanation: str
    next_steps: list[str]
    uncertainty_note: str
    source: str


def get_standard_next_steps() -> list[str]:
    """Return mandatory next steps including verified Indian cybercrime reporting."""
    return [
        "Do NOT click any links, open attachments, or share OTP/PIN/CVV with anyone.",
        "Verify your account status strictly through your bank's official mobile app or net banking portal.",
        "Never call phone numbers or WhatsApp links provided inside the message.",
        "If you suspect fraud or shared details in India, call 1930 immediately or visit https://cybercrime.gov.in.",
        "If funds were deducted, contact your bank's official 24x7 helpline to block cards, UPI, and net banking.",
    ]


def _extract_matching_phrases(message: str, pattern: str | Pattern[str]) -> list[str]:
    """Extract exact matched substrings from the original message (case-preserving)."""
    compiled = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
    matches: list[str] = []
    for match in compiled.finditer(message):
        matched_text = match.group(0).strip()
        if matched_text and matched_text not in matches:
            matches.append(matched_text)
    return matches


def analyze_with_rules(message: str) -> AnalysisResult:
    """Analyze a message with deterministic rules and return structured risk findings.

    Args:
        message: The raw text of the incoming banking message or SMS.

    Returns:
        Structured dictionary matching the BankGuard schema.
    """
    clean_message = str(message).strip() if message else ""

    # Edge cases: empty or purely non-letter content
    has_letters = bool(re.search(r"[a-zA-Z\u0900-\u097F\u0980-\u09FF]", clean_message))
    if not clean_message or not has_letters:
        return {
            "risk_level": "Low",
            "score": 0,
            "warning_signs": [],
            "suspicious_phrases": [],
            "explanation": "No readable banking or transaction content found to evaluate.",
            "next_steps": get_standard_next_steps(),
            "uncertainty_note": "Evaluated with 0 signals; rules require readable text to detect scam patterns.",
            "source": "rules",
        }

    # Mask authentic safety warnings temporarily so positive patterns don't falsely match them
    # E.g., "Never share your OTP or PIN with anyone" contains "share your OTP", but is a warning!
    message_for_positive_scan = _SAFETY_COMPILED.sub(" [GENUINE_SAFETY_WARNING] ", clean_message)

    raw_score = 0
    warning_signs: list[str] = []
    suspicious_phrases: list[str] = []
    categories_hit: set[str] = set()

    # 1. Evaluate positive signals (on text where genuine safety warnings are insulated)
    for pattern, weight, description, category in _POSITIVE_COMPILED:
        matched_chunks = _extract_matching_phrases(message_for_positive_scan, pattern)
        if not matched_chunks:
            continue
        raw_score += weight
        categories_hit.add(category)
        if description not in warning_signs:
            warning_signs.append(description)
        for chunk in matched_chunks:
            # Ensure the phrase is an exact substring of the original message
            if chunk in clean_message and chunk not in suspicious_phrases:
                suspicious_phrases.append(chunk)

    raw_score = min(raw_score, MAX_SCORE)

    asks_for_credentials = CAT_CREDENTIALS in categories_hit
    has_upi_scam = CAT_UPI in categories_hit
    has_urgency_or_threat = bool(categories_hit & _URGENCY_OR_THREAT_CATS)
    has_suspicious_link_or_app = bool(categories_hit & _LINK_OR_APP_CATS)

    # 2. Evaluate negative signals (legitimacy indicators on the full clean message)
    positive_score = raw_score
    legit_warning_found = False
    for pattern, reduction, _note, category in _NEGATIVE_COMPILED:
        # Scammers copy "never share your OTP" boilerplate; it must not offset a real request
        if category == CAT_SAFETY_ADVICE and (asks_for_credentials or has_upi_scam):
            continue
        if pattern.search(clean_message):
            raw_score = max(0, raw_score - reduction)
            if category in (CAT_SAFETY_ADVICE, CAT_GRIEVANCE):
                legit_warning_found = True

    # 3. Determine initial risk level from score
    if raw_score >= SCORE_THRESHOLD_HIGH:
        risk_level = "High"
    elif raw_score >= SCORE_THRESHOLD_MEDIUM:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 4. Enforce Safety Floors (Hard constraints)
    # Floor A: Any credential request or UPI reverse payment MUST NOT be Low
    if (asks_for_credentials or has_upi_scam) and risk_level == "Low":
        risk_level = "Medium"

    # Floor B: A suspicious link/app MUST NOT be Low, even if the message copies
    # legitimate-looking text (ledger lines, "never share OTP") to offset its score
    if has_suspicious_link_or_app and risk_level == "Low":
        risk_level = "Medium"

    # Floor C: (Link/App download) + (Urgency/Threat) + (Credentials/Payment/KYC) MUST be High
    if (
        has_suspicious_link_or_app
        and has_urgency_or_threat
        and (asks_for_credentials or has_upi_scam or bool(_KYC_WORD.search(clean_message)))
    ):
        risk_level = "High"

    # Floor D: Genuine transaction alert protection
    if (
        legit_warning_found
        and positive_score <= 15
        and not has_suspicious_link_or_app
        and not asks_for_credentials
        and not has_upi_scam
    ):
        risk_level = "Low"

    # 5. Formulate plain-language explanation
    if risk_level == "High":
        explanation = (
            f"High risk detected (Score: {raw_score}). The message exhibits clear signs of financial fraud, "
            f"such as urgency or threats combined with links, requests for credentials, or UPI tricks. "
            f"Legitimate Indian banks never ask for OTPs or PINs to credit money or update KYC via external links."
        )
    elif risk_level == "Medium":
        explanation = (
            f"Moderate risk detected (Score: {raw_score}). The message contains suspicious phrases or "
            f"urgency indicators that warrant caution. Even if this resembles a real notice, verify it "
            f"directly with your bank before taking any action or clicking any links."
        )
    elif legit_warning_found:
        explanation = (
            f"Low risk detected (Score: {raw_score}). This message resembles a standard informational alert "
            f"or transaction receipt. It includes standard bank safety advice and does not ask you to share secrets."
        )
    else:
        explanation = (
            f"Low risk detected (Score: {raw_score}). No prominent red flags or credential-harvesting patterns "
            f"were identified by the rule engine."
        )

    # Floors can raise the level above what the score alone justifies; make sure
    # the user still sees at least one reason for the classification.
    if risk_level != "Low" and not warning_signs:
        warning_signs.append("Message asks for sensitive credentials or payment authorization.")

    signs_count = len(warning_signs)
    uncertainty_note = (
        f"Based on {signs_count} rule-based signal{'s' if signs_count != 1 else ''} found; "
        f"rule-based analysis can miss novel phishing tactics or subtle context. Always independently verify."
    )

    return {
        "risk_level": risk_level,
        "score": raw_score,
        "warning_signs": warning_signs,
        "suspicious_phrases": suspicious_phrases,
        "explanation": explanation,
        "next_steps": get_standard_next_steps(),
        "uncertainty_note": uncertainty_note,
        "source": "rules",
    }
    