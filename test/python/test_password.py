"""test_password.py — Argon2id password hash / verify tests.

Security properties checked:
  - Hash returns a non-empty encoded string
  - Correct password verifies as True
  - Wrong password verifies as False
  - Each hash call produces a unique salt (output differs between calls)
  - Both str and bytes passwords are accepted
"""
from __future__ import annotations

import pytest

import nextssl


# ── basic output ─────────────────────────────────────────────────────────────

def test_password_hash_returns_string():
    h = nextssl.password_hash("password123")
    assert isinstance(h, str) and len(h) > 0


def test_password_hash_non_empty():
    assert len(nextssl.password_hash("secret")) > 8


# ── verify — correct password ─────────────────────────────────────────────────

def test_password_verify_correct_str():
    pw = "correct horse battery staple"
    assert nextssl.password_verify(pw, nextssl.password_hash(pw)) is True


def test_password_verify_correct_bytes():
    pw = b"bytes_password_\xff"
    assert nextssl.password_verify(pw, nextssl.password_hash(pw)) is True


# ── verify — wrong password ───────────────────────────────────────────────────

def test_password_verify_wrong_password():
    pw    = "right_password"
    wrong = "wrong_password"
    stored = nextssl.password_hash(pw)
    assert nextssl.password_verify(wrong, stored) is False


def test_password_verify_empty_wrong():
    stored = nextssl.password_hash("non-empty")
    assert nextssl.password_verify("", stored) is False


def test_password_verify_prefix_wrong():
    """A prefix of the correct password must not verify."""
    pw = "secret_full_password"
    stored = nextssl.password_hash(pw)
    assert nextssl.password_verify("secret_full_passwor", stored) is False


# ── salt randomness ───────────────────────────────────────────────────────────

def test_password_two_hashes_differ():
    """Argon2id salts must be unique — hashing the same password twice should differ."""
    pw = "same_password"
    h1 = nextssl.password_hash(pw)
    h2 = nextssl.password_hash(pw)
    assert h1 != h2, "identical hashes suggest missing or static salt"


# ── input types ───────────────────────────────────────────────────────────────

def test_password_hash_str_and_bytes_equivalent():
    """str and bytes versions of the same password must both verify against either hash."""
    pw_str = "match_test"
    pw_bytes = pw_str.encode()
    stored = nextssl.password_hash(pw_str)
    assert nextssl.password_verify(pw_bytes, stored) is True
