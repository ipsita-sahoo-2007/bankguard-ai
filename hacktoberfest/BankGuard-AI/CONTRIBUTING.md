# 🤝 Contributing to BankGuard AI

Thank you for contributing to BankGuard AI! This guide outlines our team development workflow, code standards, and how to safely extend our rules and sample sets.

---

## 🔒 Mandatory Security & Privacy Rule

> [!CAUTION]
> **NEVER use real personal data, real account numbers, real IFSC codes, or real phone numbers in code, tests, or documentation.**
> Always use fictional sample institutions:
> * Banks: `SampleBank`, `ABC Bank`, `XYZ Bank`
> * Fictional test numbers: `9876543210`, `9123456789`, `555-0199`
> * Accounts: `XX1234`, `A/C XX8492`
> * URLs: `https://bit.ly/sample-bank-kyc`, `http://192.168.1.50/fake.apk`

---

## 🛠️ Local Development Workflow

### 1. Prerequisites
* Python 3.11+
* Git

### 2. Setup Virtual Environment
```powershell
# Clone your fork or branch
git clone https://github.com/YOUR_USERNAME/BankGuard-AI.git
cd BankGuard-AI

# Create virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### 3. Verify Offline Tests
Before writing any new code, ensure the existing test suite passes:
```powershell
py -m pytest -q
```

---

## 🌿 Branching Strategy & Git Workflow

To prevent merge conflicts across team members, work on dedicated feature branches:

| File / Component | Branch Name Pattern | Owner Scope |
| :--- | :--- | :--- |
| `rules.py` | `feature/rules-signal-name` | Weighted rules, regex triggers, safety floors |
| `ai_client.py` | `feature/ai-integration` | Redaction, prompts, validation, model calling |
| `app.py` | `feature/ui-enhancements` | Streamlit layout, card accessibility, user flow |
| `samples.py` | `feature/samples` | Adding new fictional test scenarios |
| Documentation | `feature/docs` | README, guide updates, demo scripts |

### Creating and Submitting a Branch
```powershell
# 1. Fetch latest changes from main
git checkout main
git pull origin main

# 2. Create your feature branch
git checkout -b feature/rules-utility-scams

# 3. Make your edits and run tests
py -m pytest -q

# 4. Commit changes
git add rules.py test_rules.py
git commit -m "feat(rules): add utility disconnection threat detection"

# 5. Push to GitHub
git push -u origin feature/rules-utility-scams
```
Then open a Pull Request (PR) on GitHub against the `main` branch.

---

## 🧩 How to Add a New Rule in `rules.py`

All deterministic rules are stored in `rules.py` as clean tuples in `POSITIVE_SIGNALS` or `NEGATIVE_SIGNALS`:

```python
# In POSITIVE_SIGNALS:
(
    r"\b(?:your_regex_pattern_here)\b",
    30,  # Weight (typically 10 to 45)
    "Human-readable explanation of why this is a warning sign."
)
```

### Steps:
1. Open `rules.py`.
2. Add your regex pattern and weight to `POSITIVE_SIGNALS` (or `NEGATIVE_SIGNALS` if it's a legitimacy indicator).
3. Open `test_rules.py` and add at least one test case representing the new scam or alert.
4. Run `py test_rules.py` to confirm that all test cases match and that legitimate messages never classify as High.

---

## 📝 How to Add a Sample in `samples.py`

To provide a new fictional sample message for the UI:
1. Open `samples.py`.
2. Add an entry to `SAMPLE_MESSAGES`:
   ```python
   "new_sample_key": {
       "title": "🚨 Sample Display Title",
       "description": "Short explanation of the scam technique",
       "text": "Dear customer, SampleBank alert: ... (fictional text)",
   }
   ```
3. Ensure no real phone numbers or bank URLs are present.

---

## 🔀 Resolving Merge Conflicts Simply

If Git indicates a merge conflict:
```powershell
# 1. Ensure you are on your feature branch
git checkout feature/your-branch

# 2. Pull the latest main into your branch
git pull origin main

# 3. Git will mark conflicting files. Open the conflicted file in VS Code or Notepad.
# Look for the conflict markers:
# <<<<<<< HEAD (your changes)
# =======
# >>>>>>> main (incoming changes from main)

# 4. Edit the file to keep the desired combination of code and delete the conflict markers.

# 5. Test to verify everything passes
py -m pytest -q

# 6. Stage and commit the resolved files
git add <conflicted_file>
git commit -m "fix: resolve merge conflicts with main"
git push
```

---

## 🧼 Code Style & Guidelines

* **Pure functions in `rules.py`:** Never import Streamlit or make network calls inside `rules.py`.
* **Clean docstrings:** Include concise docstrings on all functions explaining arguments and return shapes.
* **No `print()` or logging of message text:** Never print or log user input strings anywhere in the application.
* **Keep functions focused:** Maintain small, single-purpose functions under 50 lines.

