"""Basic smoke tests for the nextssl Python bindings."""
from __future__ import annotations

import hashlib
import sys
import os

import pytest

# Support running tests both from a wheel install and from the source tree.
try:
    import nextssl
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    import nextssl


# ── Info ──────────────────────────────────────────────────────────────────────

def test_version_is_string():
    v = nextssl.version()
    assert isinstance(v, str) and len(v) > 0


def test_variant_is_known():
    assert nextssl.variant() in ("full", "lite")


def test_security_level_is_string():
    sl = nextssl.security_level()
    assert isinstance(sl, str) and len(sl) > 0


# ── Lifecycle ─────────────────────────────────────────────────────────────────

def test_init_modern():
    # profile 0 = MODERN
    nextssl.init(0)


def test_selftest_returns_zero():
    rc = nextssl.selftest()
    assert rc == 0


# ── Random ───────────────────────────────────────────────────────────────────

def test_random_correct_length():
    for n in (1, 16, 32, 64, 256):
        assert len(nextssl.random_bytes(n)) == n


def test_random_produces_different_values():
    a = nextssl.random_bytes(32)
    b = nextssl.random_bytes(32)
    assert a != b, "Two calls to random_bytes returned the same value (extremely unlikely if RNG is working)"


def test_random_zero_length_raises():
    with pytest.raises(ValueError):
        nextssl.random_bytes(0)


# ── Hash ─────────────────────────────────────────────────────────────────────

def test_hash_length():
    assert len(nextssl.hash(b"test")) == 32


def test_hash_matches_stdlib():
    data = b"hello world"
    expected = hashlib.sha256(data).digest()
    assert nextssl.hash(data) == expected


def test_hash_deterministic():
    assert nextssl.hash(b"abc") == nextssl.hash(b"abc")


def test_hash_wrong_type_raises():
    with pytest.raises(TypeError):
        nextssl.hash("not bytes")  # type: ignore[arg-type]


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

def test_encrypt_output_length():
    key = nextssl.random_bytes(32)
    pt = b"NextSSL test"
    ct = nextssl.encrypt(key, pt)
    assert len(ct) == len(pt) + 28  # 12-byte nonce + plaintext + 16-byte tag


def test_encrypt_decrypt_roundtrip():
    key = nextssl.random_bytes(32)
    for msg in (b"", b"x", b"hello world", b"\x00" * 100):
        assert nextssl.decrypt(key, nextssl.encrypt(key, msg)) == msg


def test_decrypt_wrong_key_raises():
    key       = nextssl.random_bytes(32)
    wrong_key = nextssl.random_bytes(32)
    ct = nextssl.encrypt(key, b"secret")
    with pytest.raises(nextssl.NextSSLError):
        nextssl.decrypt(wrong_key, ct)


def test_encrypt_bad_key_length_raises():
    with pytest.raises(ValueError):
        nextssl.encrypt(b"too_short", b"data")


# ── Derive Key ────────────────────────────────────────────────────────────────

def test_derive_key_length():
    ikm = b"input material"
    for n in (16, 32, 64):
        assert len(nextssl.derive_key(ikm, n)) == n


def test_derive_key_deterministic():
    ikm = b"seed"
    assert nextssl.derive_key(ikm, 32, "ctx") == nextssl.derive_key(ikm, 32, "ctx")


def test_derive_key_context_separation():
    ikm = b"seed"
    k1 = nextssl.derive_key(ikm, 32, "ctx-a")
    k2 = nextssl.derive_key(ikm, 32, "ctx-b")
    assert k1 != k2


# ── Constant Compare ─────────────────────────────────────────────────────────

def test_constant_compare_equal():
    assert nextssl.constant_compare(b"abc", b"abc") is True


def test_constant_compare_not_equal():
    assert nextssl.constant_compare(b"abc", b"xyz") is False


def test_constant_compare_different_lengths():
    assert nextssl.constant_compare(b"ab", b"abc") is False


# ── Secure Zero ───────────────────────────────────────────────────────────────

def test_secure_zero_clears_buffer():
    buf = bytearray(b"\xff" * 32)
    nextssl.secure_zero(buf)
    assert buf == bytearray(32)


def test_secure_zero_requires_bytearray():
    with pytest.raises(TypeError):
        nextssl.secure_zero(b"immutable")  # type: ignore[arg-type]
