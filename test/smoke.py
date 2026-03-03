"""Minimal smoke tests designed for post-publish verification.

These exercises are intentionally tiny so that the verification job can run
quickly yet still exercise the installed wheel.
"""

import nextssl


def test_import_and_version():
    # basic import, version string should exist and contain digits
    ver = nextssl.version()
    assert isinstance(ver, str) and "".join(ch for ch in ver if ch.isdigit())


def test_random_small():
    # ensure the CSPRNG works through the pip-installed wheel
    data = nextssl.random_bytes(8)
    assert isinstance(data, (bytes, bytearray)) and len(data) == 8


def test_variant_and_security():
    # variant should be known string, security level numeric or string
    assert isinstance(nextssl.variant(), str) and nextssl.variant()
    sec = nextssl.security_level()
    assert isinstance(sec, (str, int))


def test_init_selftest_cleanup():
    # lifecycle functions work and are idempotent
    assert nextssl.init(0) == 0
    assert nextssl.selftest() == 0
    assert nextssl.cleanup() == 0


def test_hash_and_compare():
    digest = nextssl.hash(b"abc")
    assert isinstance(digest, bytes) and len(digest) == 32
    assert nextssl.constant_compare(digest, digest)
    assert not nextssl.constant_compare(digest, b"\x00" * 32)


def test_cipher_roundtrip():
    key = nextssl.random_bytes(32)
    ct = nextssl.encrypt(key, b"hello")
    pt = nextssl.decrypt(key, ct)
    assert pt == b"hello"


def test_derive_and_kdf():
    ikm = b"secret"
    okm1 = nextssl.derive_key(ikm, 16)
    okm2 = nextssl.derive_key(ikm, 16)
    assert okm1 == okm2 and len(okm1) == 16


def test_password_functions():
    pwd = "foo123"
    h = nextssl.password_hash(pwd)
    assert isinstance(h, str)
    assert nextssl.password_verify(pwd, h)


def test_secure_zero():
    ba = bytearray(b"abcd")
    nextssl.secure_zero(ba)
    assert all(x == 0 for x in ba)
