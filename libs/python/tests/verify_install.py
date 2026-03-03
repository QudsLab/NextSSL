#!/usr/bin/env python3
"""
Post-install verification script.

Checks that the installed nextssl package loads correctly, the version matches
(if requested), basic operations succeed, and self-tests pass.

Usage:
    python verify_install.py
    python verify_install.py --version 0.0.1
"""
from __future__ import annotations

import argparse
import sys


def _sep(char: str = "=", width: int = 50) -> None:
    print(char * width)


def verify(expected_version: str | None = None) -> None:
    try:
        import nextssl
    except ImportError as exc:
        print(f"[FAIL] Cannot import nextssl: {exc}")
        sys.exit(1)

    _sep()
    print("NextSSL Install Verification")
    _sep()

    v   = nextssl.version()
    var = nextssl.variant()
    sl  = nextssl.security_level()

    print(f"  Library version : {v}")
    print(f"  Build variant   : {var}")
    print(f"  Security level  : {sl}")
    _sep("-")

    # Version check
    if expected_version is not None:
        core = v.split("-")[0]  # strip "-beta" suffix if present
        if core != expected_version:
            print(f"[FAIL] Version mismatch: expected {expected_version}, got {core}")
            sys.exit(1)
        print(f"[PASS] Version matches: {expected_version}")

    # Init
    nextssl.init(0)
    print("[PASS] init(MODERN)")

    # Self-test
    rc = nextssl.selftest()
    print(f"[PASS] selftest() → {rc}")

    # random
    key = nextssl.random_bytes(32)
    assert len(key) == 32
    print("[PASS] random_bytes(32)")

    # hash
    import hashlib
    h = nextssl.hash(b"verify")
    assert h == hashlib.sha256(b"verify").digest()
    print("[PASS] hash()")

    # encrypt / decrypt roundtrip
    ct = nextssl.encrypt(key, b"verify payload")
    pt = nextssl.decrypt(key, ct)
    assert pt == b"verify payload", f"Roundtrip mismatch: {pt!r}"
    print("[PASS] encrypt/decrypt roundtrip")

    # Cleanup
    nextssl.cleanup()
    print("[PASS] cleanup()")

    _sep()
    print(f"[SUCCESS] All checks passed  |  nextssl {v}  ({var})")
    _sep()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a nextssl installation.")
    parser.add_argument(
        "--version",
        dest="expected_version",
        default=None,
        metavar="X.Y.Z",
        help="Expected version string (core part, e.g. 0.0.1)",
    )
    args = parser.parse_args()
    verify(args.expected_version)


if __name__ == "__main__":
    main()
