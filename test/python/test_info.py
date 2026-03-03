"""test_info.py — library metadata / build-info tests."""
from __future__ import annotations

import re

import pytest

import nextssl


# ── version ───────────────────────────────────────────────────────────────────

def test_version_is_string():
    assert isinstance(nextssl.version(), str)


def test_version_not_empty():
    assert len(nextssl.version()) > 0


def test_version_semver_format():
    """Version must contain X.Y.Z optionally preceded by a product prefix.

    The C library may return full strings like ``'NextSSL v0.0.1-beta'``
    or bare semver like ``'0.0.1'``.  Strip any leading non-numeric prefix
    before matching.
    """
    raw = nextssl.version()
    # Strip optional product prefix such as 'NextSSL v'
    stripped = re.sub(r'^[A-Za-z ]+v?', '', raw).strip()
    pattern = r"^\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?$"
    assert re.match(pattern, stripped), (
        f"Unexpected version format: {raw!r} (stripped: {stripped!r})"
    )


# ── variant ───────────────────────────────────────────────────────────────────

_VALID_VARIANTS = {"full", "lite"}


def test_variant_is_known():
    assert nextssl.variant() in _VALID_VARIANTS, (
        f"Unknown variant: {nextssl.variant()!r}"
    )


def test_variant_is_string():
    assert isinstance(nextssl.variant(), str)


# ── security_level ────────────────────────────────────────────────────────────

def test_security_level_is_non_empty_string():
    sl = nextssl.security_level()
    assert isinstance(sl, str) and len(sl) > 0


def test_security_level_ascii():
    """Security level must be printable ASCII so it can be logged safely."""
    sl = nextssl.security_level()
    assert sl.isascii() and sl.isprintable(), (
        f"security_level contains non-printable chars: {sl!r}"
    )
