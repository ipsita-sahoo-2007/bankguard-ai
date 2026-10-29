"""BankGuard AI - Root Application Runner
========================================
Delegates to the modular Streamlit frontend user interface located in frontend/app.py.
Ensures seamless compatibility with Streamlit Community Cloud and npm scripts.
"""

from __future__ import annotations

import os
import sys

# Ensure root directory is in sys.path
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Load the modular frontend application
import frontend.app
