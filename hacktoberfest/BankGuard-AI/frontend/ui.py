"""BankGuard AI - UI helpers (ui.py)
Pure HTML/CSS builders. No Streamlit import, so everything here is unit-testable.
All user-supplied text is escaped before being placed in HTML.
"""

from __future__ import annotations

import html
import math
import re
from typing import Any, Mapping

SAMPLES: dict[str, str] = {
    "Genuine OTP": "123456 is your OTP for txn of Rs 500 at Amazon. Do not share this OTP with anyone. -HDFC Bank",
    "Fake KYC": "Dear Customer, your SBI KYC expired. Update immediately: http://sbi-kyc-update.xyz/login or your account will be blocked within 24 hours.",
    "UPI QR scam": "Congratulations! Scan this QR code to receive money. Enter your UPI PIN to claim the cashback credited.",
    "Remote app": "Your bank account is under review. Install AnyDesk and call 98765 43210 immediately to avoid suspension.",
    "Debit alert": "INR 1,500.00 debited from A/c XX1234 on 29-10-26. Avl Bal: INR 10,000. If not done by you, report unauthorized transaction via the official app.",
    "Bill threat": "Dear user, electricity will be disconnected tonight. Download the app: http://bit.ly/pay-now and share your OTP.",
}

LEVELS: dict[str, dict[str, str]] = {
    "Low": {"color": "#34d399", "soft": "rgba(52,211,153,.12)", "icon": "&#10003;", "headline": "Looks safe", "sub": "No scam patterns found"},
    "Medium": {"color": "#fbbf24", "soft": "rgba(251,191,36,.12)", "icon": "!", "headline": "Be careful", "sub": "Suspicious signals detected"},
    "High": {"color": "#f87171", "soft": "rgba(248,113,113,.14)", "icon": "&#10005;", "headline": "Likely a scam", "sub": "Do not interact with this message"},
}

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{--bg:#0a0f1c;--card:rgba(255,255,255,.04);--line:rgba(255,255,255,.09);--text:#e5e7eb;--muted:#94a3b8;--accent:#6366f1;--accent2:#2dd4bf;}
html,body,[class*="css"],.stApp{font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;}
.stApp{background:radial-gradient(900px 480px at 88% -8%,rgba(99,102,241,.22),transparent 60%),radial-gradient(760px 420px at -8% 2%,rgba(45,212,191,.13),transparent 55%),var(--bg);color:var(--text);}
#MainMenu,footer,header[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stDecoration"]{display:none!important;visibility:hidden;}
.block-container{max-width:1180px;padding-top:1.6rem;padding-bottom:3rem;}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes sweep{from{stroke-dashoffset:var(--len)}to{stroke-dashoffset:var(--off)}}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(45,212,191,.45)}50%{box-shadow:0 0 0 7px rgba(45,212,191,0)}}
.bg-nav{display:flex;align-items:center;justify-content:space-between;margin-bottom:2.2rem;animation:rise .5s both}
.bg-brand{display:flex;align-items:center;gap:.7rem;font-weight:800;font-size:1.15rem;letter-spacing:-.02em}
.bg-logo{width:36px;height:36px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 8px 24px rgba(99,102,241,.4)}
.bg-live{display:flex;align-items:center;gap:.5rem;font-size:.78rem;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:.35rem .8rem;background:var(--card)}
.bg-dot{width:8px;height:8px;border-radius:50%;background:var(--accent2);animation:pulse 2s infinite}
.bg-hero{text-align:center;margin-bottom:2rem;animation:rise .6s .05s both}
.bg-hero h1{font-size:clamp(2rem,4.6vw,3.3rem);font-weight:800;letter-spacing:-.035em;line-height:1.08;margin:0 0 .9rem;padding:0}
.bg-grad{background:linear-gradient(90deg,#a5b4fc,#5eead4);-webkit-background-clip:text;background-clip:text;color:transparent}
.bg-hero p{color:var(--muted);font-size:1.05rem;max-width:640px;margin:0 auto 1.2rem;line-height:1.6}
.bg-chips{display:flex;flex-wrap:wrap;justify-content:center;gap:.5rem}
.bg-chip{font-size:.78rem;font-weight:500;color:#cbd5e1;border:1px solid var(--line);background:var(--card);padding:.38rem .8rem;border-radius:999px}
.bg-card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:1.3rem 1.4rem;margin-bottom:1rem;backdrop-filter:blur(8px);animation:rise .5s both}
.bg-h{font-size:.72rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0 0 .8rem}
.bg-verdict{display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap;background:linear-gradient(135deg,var(--soft),transparent 70%),var(--card);border-color:color-mix(in srgb,var(--c) 40%,transparent)}
.bg-gauge{position:relative;width:200px;flex:none}
.bg-gauge svg{width:100%;display:block}
.bg-gauge .arc{stroke-dasharray:var(--len);stroke-dashoffset:var(--off);animation:sweep 1.1s cubic-bezier(.2,.8,.2,1) both}
.bg-score{position:absolute;left:0;right:0;bottom:2px;text-align:center;font-variant-numeric:tabular-nums}
.bg-score b{font-size:2.3rem;font-weight:800;letter-spacing:-.04em;line-height:1}
.bg-score span{font-size:.8rem;color:var(--muted)}
.bg-badge{display:inline-flex;align-items:center;gap:.45rem;font-weight:700;font-size:.8rem;letter-spacing:.06em;text-transform:uppercase;color:var(--c);background:var(--soft);border:1px solid color-mix(in srgb,var(--c) 45%,transparent);padding:.3rem .75rem;border-radius:999px}
.bg-verdict h2{font-size:1.7rem;font-weight:800;letter-spacing:-.03em;margin:.6rem 0 .2rem;padding:0}
.bg-verdict p{margin:0;color:var(--muted);font-size:.95rem}
.bg-msg{font-size:.95rem;line-height:1.75;color:#cbd5e1;word-break:break-word}
.bg-msg mark{background:color-mix(in srgb,#f87171 28%,transparent);color:#fecaca;border-bottom:2px solid #f87171;border-radius:4px;padding:.05em .25em}
.bg-sign{display:flex;gap:.75rem;align-items:flex-start;padding:.7rem 0;border-top:1px solid var(--line);font-size:.92rem;line-height:1.5;color:#d1d5db}
.bg-sign:first-of-type{border-top:0;padding-top:0}
.bg-ico{flex:none;width:24px;height:24px;border-radius:8px;display:grid;place-items:center;font-size:.8rem;font-weight:800;color:#fbbf24;background:rgba(251,191,36,.13)}
.bg-note{font-size:.84rem;color:var(--muted);border-left:3px solid var(--accent);padding:.1rem 0 .1rem .8rem;margin-top:.9rem;line-height:1.55}
.bg-step{display:flex;gap:.8rem;padding:.55rem 0;font-size:.92rem;line-height:1.5;color:#d1d5db}
.bg-num{flex:none;width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-size:.75rem;font-weight:700;color:#a5b4fc;background:rgba(99,102,241,.16)}
.bg-sos{display:flex;flex-wrap:wrap;gap:.8rem;align-items:center;justify-content:space-between;background:linear-gradient(135deg,rgba(99,102,241,.2),rgba(45,212,191,.1));border-color:rgba(99,102,241,.4)}
.bg-sos b{font-size:1rem}.bg-sos span{display:block;font-size:.84rem;color:var(--muted);margin-top:.15rem}
.bg-cta{display:inline-block;text-decoration:none!important;font-weight:600;font-size:.88rem;color:#fff!important;background:linear-gradient(135deg,var(--accent),#4f46e5);padding:.6rem 1rem;border-radius:11px;margin-left:.4rem;transition:transform .15s,box-shadow .15s}
.bg-cta.alt{background:var(--card);border:1px solid var(--line);color:var(--text)!important}
.bg-cta:hover{transform:translateY(-1px);box-shadow:0 8px 22px rgba(99,102,241,.35)}
.bg-empty{text-align:center;padding:3.2rem 1.5rem;border:1.5px dashed var(--line);border-radius:18px;color:var(--muted);animation:rise .5s both}
.bg-empty .em{width:64px;height:64px;margin:0 auto 1rem;border-radius:20px;display:grid;place-items:center;font-size:1.8rem;background:linear-gradient(135deg,rgba(99,102,241,.25),rgba(45,212,191,.18))}
.bg-empty b{display:block;color:var(--text);font-size:1.05rem;margin-bottom:.3rem}
.bg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.9rem}
.bg-mini{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:1.1rem 1.2rem;transition:transform .2s,border-color .2s}
.bg-mini:hover{transform:translateY(-3px);border-color:rgba(99,102,241,.5)}
.bg-mini b{display:block;margin-bottom:.35rem;font-size:.98rem}.bg-mini p{margin:0;color:var(--muted);font-size:.88rem;line-height:1.55}
.bg-foot{text-align:center;color:#64748b;font-size:.78rem;margin-top:2.5rem;line-height:1.7}
div.stButton>button,div.stDownloadButton>button{border-radius:12px;border:1px solid var(--line);background:var(--card);color:var(--text);font-weight:600;padding:.55rem 1rem;transition:all .15s;width:100%}
div.stButton>button:hover,div.stDownloadButton>button:hover{border-color:rgba(99,102,241,.7);background:rgba(99,102,241,.12);color:#fff;transform:translateY(-1px)}
div.stButton>button[kind="primary"],div.stButton>button[data-testid="stBaseButton-primary"]{background:linear-gradient(135deg,#6366f1,#4f46e5);border:0;color:#fff;box-shadow:0 10px 26px rgba(99,102,241,.38)}
div.stButton>button[kind="primary"]:hover,div.stButton>button[data-testid="stBaseButton-primary"]:hover{filter:brightness(1.1);color:#fff}
div[data-testid="stTextArea"] textarea{background:rgba(255,255,255,.03)!important;border:1px solid var(--line)!important;border-radius:14px!important;font-size:.97rem;line-height:1.6;color:var(--text)!important}
div[data-testid="stTextArea"] textarea:focus{border-color:var(--accent)!important;box-shadow:0 0 0 3px rgba(99,102,241,.25)!important}
button[data-baseweb="tab"]{font-weight:600;color:var(--muted)}
button[data-baseweb="tab"][aria-selected="true"]{color:#fff}
:focus-visible{outline:2px solid var(--accent2)!important;outline-offset:2px}
@media (max-width:640px){.bg-nav{flex-direction:column;gap:.8rem}.bg-gauge{width:100%;max-width:240px;margin:0 auto}.bg-cta{margin:.3rem .4rem 0 0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

SHIELD_SVG = (
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6l8-3z"/>'
    '<path d="M8.5 12l2.5 2.5L15.5 9.5"/></svg>'
)


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def hero_html() -> str:
    return (
        '<div class="bg-nav"><div class="bg-brand"><div class="bg-logo">' + SHIELD_SVG + '</div>BankGuard&nbsp;AI</div>'
        '<div class="bg-live"><span class="bg-dot"></span>Rule engine online &middot; runs offline</div></div>'
        '<div class="bg-hero"><h1>Spot banking scams<br><span class="bg-grad">before they spot you.</span></h1>'
        '<p>Paste any suspicious SMS, UPI request or KYC alert. BankGuard explains exactly what is wrong, '
        'in plain language, and tells you what to do next.</p>'
        '<div class="bg-chips"><span class="bg-chip">&#128274; Nothing is stored</span>'
        '<span class="bg-chip">&#9889; Instant analysis</span><span class="bg-chip">&#127470;&#127475; Built for India</span>'
        '<span class="bg-chip">&#128269; Explainable results</span></div></div>'
    )


def empty_html() -> str:
    return (
        '<div class="bg-empty"><div class="em">&#128737;</div><b>Your analysis will appear here</b>'
        'Paste a message on the left, or try one of the samples, then press Analyze.</div>'
    )


def gauge_html(score: int, level: str) -> str:
    meta = LEVELS[level]
    length = math.pi * 90
    offset = length * (1 - max(0, min(100, score)) / 100)
    return (
        f'<div class="bg-gauge" role="img" aria-label="Risk score {score} out of 100, {level} risk">'
        f'<svg viewBox="0 0 220 120"><path d="M20 110 A90 90 0 0 1 200 110" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="14" stroke-linecap="round"/>'
        f'<path class="arc" style="--len:{length:.2f};--off:{offset:.2f}" d="M20 110 A90 90 0 0 1 200 110" fill="none" '
        f'stroke="{meta["color"]}" stroke-width="14" stroke-linecap="round"/></svg>'
        f'<div class="bg-score"><b>{int(score)}</b><span> / 100</span></div></div>'
    )


def highlight_html(message: str, phrases: list[str]) -> str:
    """Escape the message and wrap each flagged phrase in <mark>."""
    message = message.replace("\r", "")
    cleaned = sorted({p for p in phrases if p}, key=len, reverse=True)
    if not cleaned:
        return _e(message).replace("\n", "<br>")
    pattern = re.compile("|".join(re.escape(p) for p in cleaned), re.IGNORECASE)
    out: list[str] = []
    last = 0
    for m in pattern.finditer(message):
        out.append(_e(message[last:m.start()]))
        out.append(f"<mark>{_e(m.group(0))}</mark>")
        last = m.end()
    out.append(_e(message[last:]))
    return "".join(out).replace("\n", "<br>")


def result_html(result: Mapping[str, Any], message: str) -> str:
    level = result["risk_level"] if result["risk_level"] in LEVELS else "Medium"
    meta = LEVELS[level]
    style = f'--c:{meta["color"]};--soft:{meta["soft"]}'
    parts = [
        f'<div class="bg-card bg-verdict" style="{style}">{gauge_html(result["score"], level)}<div>'
        f'<span class="bg-badge"><span aria-hidden="true">{meta["icon"]}</span>{_e(level)} risk</span>'
        f'<h2>{meta["headline"]}</h2><p>{meta["sub"]}</p></div></div>'
    ]
    parts.append(
        '<div class="bg-card"><div class="bg-h">Message, with red flags highlighted</div>'
        f'<div class="bg-msg">{highlight_html(message, list(result["suspicious_phrases"]))}</div></div>'
    )
    signs = "".join(
        f'<div class="bg-sign"><span class="bg-ico" aria-hidden="true">!</span><span>{_e(s)}</span></div>'
        for s in result["warning_signs"]
    )
    why = signs or '<div class="bg-sign"><span class="bg-ico" style="color:#34d399;background:rgba(52,211,153,.13)" aria-hidden="true">&#10003;</span><span>No scam patterns were found.</span></div>'
    parts.append(
        f'<div class="bg-card"><div class="bg-h">Why this verdict</div>{why}'
        f'<div class="bg-note">{_e(result["explanation"])}</div>'
        f'<div class="bg-note" style="border-color:#475569">{_e(result["uncertainty_note"])}</div></div>'
    )
    steps = "".join(
        f'<div class="bg-step"><span class="bg-num">{i}</span><span>{_e(s)}</span></div>'
        for i, s in enumerate(result["next_steps"], 1)
    )
    parts.append(f'<div class="bg-card"><div class="bg-h">What to do now</div>{steps}</div>')
    parts.append(
        '<div class="bg-card bg-sos"><div><b>Already shared details or lost money?</b>'
        '<span>Act within the first hour. Report fast to improve the chance of recovery.</span></div><div>'
        '<a class="bg-cta" href="tel:1930">&#9742; Call 1930</a>'
        '<a class="bg-cta alt" href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a></div></div>'
    )
    return "".join(parts)


def learn_html() -> dict[str, str]:
    def cards(items: list[tuple[str, str]]) -> str:
        return '<div class="bg-grid">' + "".join(f'<div class="bg-mini"><b>{t}</b><p>{d}</p></div>' for t, d in items) + "</div>"

    return {
        "How it works": cards([
            ("1. Weighted signals", "Every message is checked against dozens of scam patterns: credential requests, urgency, fake links, risky apps."),
            ("2. Genuine-alert detection", "Real bank warnings like &ldquo;never share your OTP&rdquo; are recognised and never mistaken for a scam."),
            ("3. Safety floors", "Hard rules stop dangerous under-rating, e.g. a link plus a threat plus a KYC demand is always High."),
        ]),
        "Common scams": cards([
            ("Fake KYC update", "Claims your KYC expired and pushes a link. Banks do not ask for KYC through SMS links."),
            ("UPI QR / collect", "You never need a PIN or QR scan to <em>receive</em> money. A PIN only sends money out."),
            ("Remote-access apps", "AnyDesk or TeamViewer lets a stranger see and control your phone. Never install them for &ldquo;support&rdquo;."),
            ("APK downloads", "Apps outside the Play Store can read your SMS and OTPs."),
            ("Bill / SIM threats", "&ldquo;Power will be cut tonight&rdquo; creates panic so you call a fake number."),
            ("Lottery &amp; cashback", "Free rewards are bait to get your details or a small &ldquo;fee&rdquo;."),
        ]),
        "Privacy": cards([
            ("Runs locally", "Analysis is a deterministic rule engine. No AI API call is made."),
            ("Nothing stored", "Messages stay in your browser session and are discarded when you close the tab."),
            ("Not a guarantee", "Rules can miss brand-new tactics. Always verify through your bank&rsquo;s official app."),
        ]),
    }


def footer_html() -> str:
    return (
        '<div class="bg-foot">BankGuard AI is an assistive tool, not a substitute for your bank. '
        'Rule-based detection can miss new scams.<br>Cyber fraud helpline <b>1930</b> &middot; '
        '<a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" style="color:#a5b4fc">cybercrime.gov.in</a></div>'
    )


def report_text(result: Mapping[str, Any], message: str) -> str:
    lines = [
        "BANKGUARD AI - ANALYSIS REPORT",
        "=" * 34,
        f"Risk level : {result['risk_level']}",
        f"Score      : {result['score']} / 100",
        "",
        "Message:",
        message.strip(),
        "",
        "Why:",
        *[f"  - {s}" for s in result["warning_signs"]],
        "",
        result["explanation"],
        result["uncertainty_note"],
        "",
        "What to do now:",
        *[f"  {i}. {s}" for i, s in enumerate(result["next_steps"], 1)],
    ]
    return "\n".join(lines)
