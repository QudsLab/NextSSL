"""test_utils.py — secure_zero and constant_compare tests.

Security properties checked:
  - constant_compare: equal / not-equal / different-length
  - constant_compare: common-prefix attack — same prefix should not short-circuit
  - secure_zero: all bytes set to zero
  - secure_zero: immutable input rejected
"""
from __future__ import annotations

import pytest

import nextssl


# ── constant_compare ─────────────────────────────────────────────────────────

def test_constant_compare_equal():
    assert nextssl.constant_compare(b"abc", b"abc") is True


def test_constant_compare_not_equal():
    assert nextssl.constant_compare(b"abc", b"xyz") is False


def test_constant_compare_different_lengths():
    assert nextssl.constant_compare(b"ab", b"abc") is False


def test_constant_compare_empty_equal():
    assert nextssl.constant_compare(b"", b"") is True


def test_constant_compare_empty_vs_nonempty():
    assert nextssl.constant_compare(b"", b"x") is False


def test_constant_compare_common_prefix():
    """Inputs that share a long prefix but differ only at the last byte must compare False."""
    base = b"\x00" * 31
    a = base + b"\x00"
    b = base + b"\x01"
    assert nextssl.constant_compare(a, b) is False


def test_constant_compare_binary_data():
    data = bytes(range(256))
    assert nextssl.constant_compare(data, data) is True
    modified = bytes(range(1, 256)) + b"\x00"
    assert nextssl.constant_compare(data, modified) is False


def test_constant_compare_all_zeros_vs_all_ones():
    assert nextssl.constant_compare(b"\x00" * 32, b"\xff" * 32) is False


# ── secure_zero ───────────────────────────────────────────────────────────────

def test_secure_zero_clears_all_bytes():
    buf = bytearray(b"\xff" * 64)
    nextssl.secure_zero(buf)
    assert buf == bytearray(64), "secure_zero did not clear all bytes to zero"


def test_secure_zero_works_on_single_byte():
    buf = bytearray(b"\xde")
    nextssl.secure_zero(buf)
    assert buf == bytearray(1)


def test_secure_zero_works_on_large_buffer():
    buf = bytearray(b"\xab" * 4096)
    nextssl.secure_zero(buf)
    assert buf == bytearray(4096)


def test_secure_zero_requires_bytearray():
    with pytest.raises(TypeError):
        nextssl.secure_zero(b"immutable bytes")  # type: ignore[arg-type]


def test_secure_zero_requires_bytearray_not_str():
    with pytest.raises(TypeError):
        nextssl.secure_zero("string")  # type: ignore[arg-type]
