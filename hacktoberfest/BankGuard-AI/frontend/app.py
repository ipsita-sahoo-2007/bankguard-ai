"""BankGuard AI - Streamlit frontend. Run with:  streamlit run app.py"""

from __future__ import annotations

import streamlit as st

import ui
from rules import analyze_with_rules

st.set_page_config(
    page_title="BankGuard AI | Banking scam & phishing shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(f"<style>{ui.CSS}</style>", unsafe_allow_html=True)
st.markdown(ui.hero_html(), unsafe_allow_html=True)

st.session_state.setdefault("msg", "")
st.session_state.setdefault("result", None)
st.session_state.setdefault("analyzed", "")
st.session_state.setdefault("empty_warning", False)


def _load_sample(text: str) -> None:
    st.session_state.msg = text
    st.session_state.result = None
    st.session_state.empty_warning = False


def _clear() -> None:
    st.session_state.msg = ""
    st.session_state.result = None
    st.session_state.empty_warning = False


left, right = st.columns([1.05, 1], gap="large")

with left:
    st.markdown('<div class="bg-h">Paste a message</div>', unsafe_allow_html=True)
    st.text_area(
        "Suspicious message",
        key="msg",
        height=220,
        max_chars=2000,
        placeholder="Paste an SMS, WhatsApp text, UPI request or email here...",
        label_visibility="collapsed",
    )

    analyze_col, clear_col = st.columns([2, 1])
    with analyze_col:
        analyze = st.button("Analyze message", type="primary", key="analyze")
    with clear_col:
        st.button("Clear", key="clear", on_click=_clear)

    if analyze:
        text = st.session_state.msg.strip()
        if text:
            st.session_state.result = analyze_with_rules(text)
            st.session_state.analyzed = text
            st.session_state.empty_warning = False
        else:
            st.session_state.result = None
            st.session_state.empty_warning = True

    if st.session_state.empty_warning:
        st.warning("Please paste a message first.")

    st.markdown('<div class="bg-h" style="margin-top:1.4rem">Or try a sample</div>', unsafe_allow_html=True)
    names = list(ui.SAMPLES)
    for row_start in range(0, len(names), 3):
        cols = st.columns(3)
        for col, name in zip(cols, names[row_start:row_start + 3]):
            with col:
                st.button(name, key=f"sample_{name}", on_click=_load_sample, args=(ui.SAMPLES[name],))

with right:
    result = st.session_state.result
    if result is None:
        st.markdown(ui.empty_html(), unsafe_allow_html=True)
    else:
        st.markdown(ui.result_html(result, st.session_state.analyzed), unsafe_allow_html=True)
        st.download_button(
            "Download report (.txt)",
            data=ui.report_text(result, st.session_state.analyzed),
            file_name="bankguard-report.txt",
            mime="text/plain",
        )

st.markdown("<div style='height:1.6rem'></div>", unsafe_allow_html=True)
tabs = st.tabs(list(ui.learn_html()))
for tab, content in zip(tabs, ui.learn_html().values()):
    with tab:
        st.markdown(content, unsafe_allow_html=True)

st.markdown(ui.footer_html(), unsafe_allow_html=True)