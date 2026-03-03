"""test_cipher.py — AES-256-GCM encrypt / decrypt tests.

Security properties checked:
  - Correct output length (nonce + ct + tag = len(pt) + 28)
  - Encrypt → decrypt roundtrip
  - Authentication tag failure on wrong key
  - Authentication tag failure on tampered ciphertext
  - Nonce freshness — two encryptions of same plaintext differ
  - Key length validation
"""
from __future__ import annotations

import pytest

import nextssl
from nextssl import NextSSLError

# AES-256-GCM overhead: 12-byte nonce + 16-byte tag
_OVERHEAD = 28


# ── output length ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pt_len", [0, 1, 15, 16, 31, 32, 100, 1024])
def test_encrypt_output_length(pt_len: int):
    key = nextssl.random_bytes(32)
    ct = nextssl.encrypt(key, b"\xab" * pt_len)
    assert len(ct) == pt_len + _OVERHEAD


# ── roundtrip ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("plaintext", [
    b"",
    b"x",
    b"hello NextSSL",
    b"\x00" * 64,
    b"\xff" * 64,
    bytes(range(256)),
])
def test_encrypt_decrypt_roundtrip(plaintext: bytes):
    key = nextssl.random_bytes(32)
    assert nextssl.decrypt(key, nextssl.encrypt(key, plaintext)) == plaintext


# ── authentication failure ────────────────────────────────────────────────────

def test_wrong_key_raises():
    key       = nextssl.random_bytes(32)
    wrong_key = nextssl.random_bytes(32)
    ct = nextssl.encrypt(key, b"secret payload")
    with pytest.raises(NextSSLError):
        nextssl.decrypt(wrong_key, ct)


def test_tampered_tag_raises():
    key = nextssl.random_bytes(32)
    ct = bytearray(nextssl.encrypt(key, b"tamper me"))
    ct[-1] ^= 0xFF                       # flip last byte of auth tag
    with pytest.raises(NextSSLError):
        nextssl.decrypt(key, bytes(ct))


def test_tampered_ciphertext_body_raises():
    key = nextssl.random_bytes(32)
    ct = bytearray(nextssl.encrypt(key, b"body tamper"))
    # flip a byte in the ciphertext body (after 12-byte nonce, before 16-byte tag)
    ct[12] ^= 0x01
    with pytest.raises(NextSSLError):
        nextssl.decrypt(key, bytes(ct))


def test_tampered_nonce_raises():
    key = nextssl.random_bytes(32)
    ct = bytearray(nextssl.encrypt(key, b"nonce tamper"))
    ct[0] ^= 0x01                        # flip first byte of nonce
    with pytest.raises(NextSSLError):
        nextssl.decrypt(key, bytes(ct))


# ── nonce freshness ────────────────────────────────────────────────────────────

def test_each_encryption_is_unique():
    """Same key + same plaintext must never produce the same ciphertext."""
    key = nextssl.random_bytes(32)
    pt  = b"same message"
    ct1 = nextssl.encrypt(key, pt)
    ct2 = nextssl.encrypt(key, pt)
    assert ct1 != ct2, "deterministic nonce — ciphertext reuse detected"


def test_bulk_ciphertexts_unique():
    """16 encryptions of the same plaintext must all be distinct."""
    key   = nextssl.random_bytes(32)
    items = [nextssl.encrypt(key, b"same") for _ in range(16)]
    assert len(set(items)) == 16, "duplicate ciphertexts in bulk encryption"


# ── key validation ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_key", [b"", b"tooshort", b"\x00" * 16, b"\x00" * 31])
def test_short_key_raises(bad_key: bytes):
    with pytest.raises(ValueError):
        nextssl.encrypt(bad_key, b"data")


def test_long_key_raises():
    with pytest.raises(ValueError):
        nextssl.encrypt(b"\x00" * 33, b"data")
