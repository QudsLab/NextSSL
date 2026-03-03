"""Root conftest — bootstrap sys.path so nextssl is importable without installing.

Applies to both test/test_python.py and test/python/* when pytest is invoked
from the project root:
    pytest test/
    pytest test/python/
    python  test/test_python.py
"""
from __future__ import annotations

import os
import sys

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "libs", "python", "src")
)
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
