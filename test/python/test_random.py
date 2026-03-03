"""test_random.py — CSPRNG / random_bytes tests.

Security properties checked:
  - Exact output length
  - Statistical uniqueness (two calls do not collide)
  - No all-zero blocks (basic output sanity)
  - Rejection of invalid lengths
"""
from __future__ import annotations

import pytest

import nextssl


# ── length ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("n", [1, 8, 16, 32, 64, 128, 256, 1024])
def test_random_correct_length(n: int):
    assert len(nextssl.random_bytes(n)) == n


def test_random_returns_bytes():
    assert isinstance(nextssl.random_bytes(16), bytes)


# ── uniqueness / distinctness ─────────────────────────────────────────────────

def test_random_two_calls_differ():
    """Identical consecutive calls must produce distinct outputs."""
    a = nextssl.random_bytes(32)
    b = nextssl.random_bytes(32)
    assert a != b, "two random_bytes(32) calls returned the same value"


def test_random_bulk_unique():
    """Generate 64 × 32-byte values; all must be distinct."""
    values = [nextssl.random_bytes(32) for _ in range(64)]
    assert len(set(values)) == 64, "duplicate values in bulk random generation"


# ── entropy sanity ────────────────────────────────────────────────────────────

def test_random_no_all_zero_block():
    """32-byte output must not be all-zero (would indicate a broken RNG)."""
    out = nextssl.random_bytes(32)
    assert out != b"\x00" * 32


def test_random_no_all_ff_block():
    out = nextssl.random_bytes(32)
    assert out != b"\xff" * 32


def test_random_large_output_has_variance():
    """4 KiB of random output must contain at least two distinct byte values."""
    out = nextssl.random_bytes(4096)
    assert len(set(out)) > 64, "insufficient byte variety in 4 KiB random output"


# ── error handling ────────────────────────────────────────────────────────────

def test_random_zero_length_raises():
    with pytest.raises(ValueError):
        nextssl.random_bytes(0)


def test_random_negative_length_raises():
    with pytest.raises((ValueError, OverflowError)):
        nextssl.random_bytes(-1)
