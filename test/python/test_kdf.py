"""test_kdf.py — HKDF-SHA256 key derivation tests.

Security properties checked:
  - Correct output length for various requested sizes
  - Determinism (same IKM + context → same key)
  - Context / domain separation
  - IKM separation
  - Output uniformity (no all-zero output)
"""
from __future__ import annotations

import pytest

import nextssl


# ── output length ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("length", [1, 16, 32, 64, 128, 255])
def test_derive_key_output_length(length: int):
    dk = nextssl.derive_key(b"input key material", length)
    assert len(dk) == length


def test_derive_key_returns_bytes():
    assert isinstance(nextssl.derive_key(b"ikm", 32), bytes)


# ── determinism ───────────────────────────────────────────────────────────────

def test_derive_key_deterministic_no_context():
    ikm = b"seed material"
    assert nextssl.derive_key(ikm, 32) == nextssl.derive_key(ikm, 32)


def test_derive_key_deterministic_with_context():
    ikm = b"seed material"
    ctx = "app-context-v1"
    assert nextssl.derive_key(ikm, 32, ctx) == nextssl.derive_key(ikm, 32, ctx)


# ── context / domain separation ───────────────────────────────────────────────

def test_derive_key_different_context():
    ikm = b"same seed"
    k1 = nextssl.derive_key(ikm, 32, "ctx-a")
    k2 = nextssl.derive_key(ikm, 32, "ctx-b")
    assert k1 != k2, "different contexts must produce different keys"


def test_derive_key_context_vs_no_context():
    ikm = b"same seed"
    k1 = nextssl.derive_key(ikm, 32)
    k2 = nextssl.derive_key(ikm, 32, "ctx")
    assert k1 != k2


# ── IKM separation ────────────────────────────────────────────────────────────

def test_derive_key_different_ikm():
    ctx = "same-context"
    k1 = nextssl.derive_key(b"ikm-alpha", 32, ctx)
    k2 = nextssl.derive_key(b"ikm-beta",  32, ctx)
    assert k1 != k2, "different IKMs must produce different keys"


def test_derive_key_similar_ikm_differs():
    """Near-identical IKMs (1-bit difference) must produce distinct keys."""
    ikm_a = bytearray(32)
    ikm_b = bytearray(32)
    ikm_b[0] ^= 0x01
    assert nextssl.derive_key(bytes(ikm_a), 32) != nextssl.derive_key(bytes(ikm_b), 32)


# ── output sanity ─────────────────────────────────────────────────────────────

def test_derive_key_not_all_zeros():
    dk = nextssl.derive_key(b"some key material", 32)
    assert dk != b"\x00" * 32


# ── error handling ────────────────────────────────────────────────────────────

def test_derive_key_zero_length_raises():
    with pytest.raises((ValueError, Exception)):
        nextssl.derive_key(b"ikm", 0)
