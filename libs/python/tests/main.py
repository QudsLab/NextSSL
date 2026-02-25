#!/usr/bin/env python3
"""NextSSL test suite entry point."""

import sys
import pathlib

# Ensure utils/ is importable
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from utils import run_all

sys.exit(run_all())
