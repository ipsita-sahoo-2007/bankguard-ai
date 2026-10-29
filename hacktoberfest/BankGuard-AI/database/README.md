# 🗄️ Database Layer & Zero-Retention Architecture

## 🔒 Privacy & Architecture Notice

BankGuard AI operates under a **strict Zero-User-Data Retention Policy**:
* **No User Databases:** We deliberately do NOT run a database for user messages, bank credentials, session history, or telemetry.
* **No Persistence:** User inputs are processed ephemerally in-memory during the analysis turn and immediately discarded.
* **Educational Purpose:** Storing financial text or transaction SMS creates privacy risks for end users. BankGuard strictly avoids any credential persistence.

## 📁 What is Contained in this Folder
This directory houses **purely static reference datasets and offline test fixtures**:
1. **`samples.py`:** Fictional banking alerts (KYC, OTP, UPI scam, Legitimate alert) used for testing and UI demonstration.
2. **`reference_data.py`:** Static registries of verified official Indian banking domains and official national cybercrime reporting resources (Helpline 1930 & https://cybercrime.gov.in).

