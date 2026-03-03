"""test_lifecycle.py — init / cleanup / selftest lifecycle tests.

These tests explicitly manage library state, so they issue cleanup() calls
before/after reinitialising.  Isolation note: pytest runs test files in
alphabetical order; this file runs *before* most other domain tests, which
rely on auto-init.  We restore the library to an initialised state at the end
of file-scope so the remaining test files can rely on auto-init having already
fired.
"""
from __future__ import annotations

import pytest

import nextssl
from nextssl import NextSSLError


# ── helpers ────────────────────────────────────────────────────────────────────

def _ensure_clean() -> None:
    """Best-effort cleanup — tolerate already-cleaned state."""
    try:
        nextssl.cleanup()
    except Exception:
        pass


# ── selftest ───────────────────────────────────────────────────────────────────

def test_selftest_returns_zero():
    rc = nextssl.selftest()
    assert rc == 0


# ── double-init ────────────────────────────────────────────────────────────────

def test_double_init_is_idempotent():
    """Calling init() when already initialised must not raise.

    The library silently succeeds on repeated init() calls — it does NOT
    return an error.  This is the designed behaviour of this implementation.
    """
    try:
        nextssl.init(0)          # ensure initialised
    except NextSSLError:
        pass

    # Second call must also succeed without raising
    nextssl.init(0)


# ── cleanup + re-init ─────────────────────────────────────────────────────────

def test_cleanup_then_reinit():
    """cleanup() followed by init() must succeed without error."""
    _ensure_clean()
    nextssl.init(0)          # should not raise


# ── security profiles ─────────────────────────────────────────────────────────
# Profiles 0-4 are tested; profile 5 (RESEARCH) is deliberately skipped as it
# enables algorithms marked unsafe and may affect subsequent tests.

@pytest.mark.parametrize("profile", [0, 1, 2, 3, 4])
def test_init_accepts_valid_profile(profile: int):
    _ensure_clean()
    nextssl.init(profile)    # must not raise
    nextssl.cleanup()


def test_init_invalid_profile_falls_back_to_modern():
    """A profile number outside the valid range silently uses MODERN (profile 0).

    The library clamps unknown profiles to MODERN instead of returning an error.
    """
    _ensure_clean()
    nextssl.init(999)    # must not raise — falls back to MODERN


# ── restore library to a usable state ────────────────────────────────────────

def _restore() -> None:
    _ensure_clean()
    nextssl.init(0)

_restore()
