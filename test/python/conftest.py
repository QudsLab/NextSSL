"""conftest for test/python/ — path bootstrap + shared helpers.

Individual test modules call nextssl.cleanup() / nextssl.init() when they need
to control lifecycle state.  All other modules rely on the library's auto-init
behaviour (first C call automatically initialises with MODERN profile).
"""
from __future__ import annotations

import os
import sys

# belt-and-suspenders: cover direct `pytest test/python/` invocations
_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "libs", "python", "src")
)
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
