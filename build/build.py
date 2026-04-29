#!/usr/bin/env python3
"""build.py — NextSSL build helper entry point.

Usage:
    python build/build.py                     # Default: run checks only (no compile yet)
    python build/build.py --check             # Export + algo audit
    python build/build.py --list-features     # List all feature flags
    python build/build.py --feature ML_KEM    # Toggle/show specific feature

Works with any Python 3.8+ interpreter on PATH. No virtual environment is required.
"""
import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import PROJECT_ROOT, FEATURE_FLAGS

BUILD_DIR = Path(__file__).resolve().parent


def run_check(script_name: str) -> int:
    """Run a check script and return its exit code."""
    script = BUILD_DIR / script_name
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode


def cmd_check():
    """Run all audit checks."""
    print("\n>>> Running export audit...\n")
    rc1 = run_check("check_exports.py")

    print("\n>>> Running algorithm coverage...\n")
    rc2 = run_check("check_algos.py")

    if rc1 == 0 and rc2 == 0:
        print("\n✅ All checks passed.\n")
    else:
        print(f"\n⚠️  Issues found (export={rc1}, algo={rc2}).\n")
    return rc1 or rc2


def cmd_list_features():
    """List all feature flags and their status."""
    print("\n  NextSSL Feature Flags")
    print("  " + "-" * 40)
    for flag, enabled in sorted(FEATURE_FLAGS.items()):
        status = "✅ ON" if enabled else "❌ OFF"
        print(f"  {status}  {flag}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NextSSL build checks using system Python (no virtualenv required)"
    )
    parser.add_argument("--check", action="store_true",
                        help="Run export + algorithm audit checks")
    parser.add_argument("--list-features", action="store_true",
                        help="List all feature flags")
    parser.add_argument("--feature", type=str,
                        help="Show/toggle a specific feature flag")
    args = parser.parse_args()

    if args.list_features:
        cmd_list_features()
        return 0

    if args.feature:
        flag = args.feature
        # Try to match with or without ENABLE_ prefix
        for key in FEATURE_FLAGS:
            if flag.upper() in key:
                status = "ON" if FEATURE_FLAGS[key] else "OFF"
                print(f"  {key} = {status}")
                return 0
        print(f"  Unknown feature: {flag}")
        return 1

    # Default: run checks
    return cmd_check()


if __name__ == "__main__":
    sys.exit(main() or 0)
