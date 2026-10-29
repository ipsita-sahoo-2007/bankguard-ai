"""BankGuard AI - Frontend Styles (frontend/styles.py)
====================================================
Static accessible CSS for mobile-first Streamlit card rendering.
No dynamic variables are interpolated here to ensure complete XSS immunity.
"""

STATIC_CSS = """
<style>
/* Responsive layout & typography */
.main .block-container {
    max-width: 760px;
    padding-top: 1.5rem;
    padding-bottom: 3rem;
}
.stTextArea textarea {
    font-size: 1rem;
    line-height: 1.5;
    border-radius: 8px;
}
div.stButton > button {
    border-radius: 8px;
    padding: 0.5rem 1rem;
    font-weight: 600;
}
/* Accessible card containers */
.badge-card {
    padding: 1.25rem;
    border-radius: 10px;
    margin-bottom: 1.25rem;
    border-left: 6px solid;
}
.badge-high {
    background-color: #FEF2F2;
    border-color: #DC2626;
    color: #991B1B;
}
.badge-medium {
    background-color: #FFFBEB;
    border-color: #D97706;
    color: #92400E;
}
.badge-low {
    background-color: #F0FDF4;
    border-color: #16A34A;
    color: #166534;
}
.phrase-chip {
    display: inline-block;
    background-color: #FEE2E2;
    color: #991B1B;
    padding: 0.2rem 0.55rem;
    margin: 0.2rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.9rem;
    border: 1px solid #FCA5A5;
}
.info-card {
    background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
}
</style>
"""

