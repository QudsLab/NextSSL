"""
nextssl — Python bindings for the NextSSL cryptographic library.

Quick start::

    import nextssl

    nextssl.init()                          # optional — auto-called on first use

    key        = nextssl.random_bytes(32)
    ciphertext = nextssl.encrypt(key, b"hello world")
    plaintext  = nextssl.decrypt(key, ciphertext)
    assert plaintext == b"hello world"

    stored = nextssl.password_hash("my_password")
    assert nextssl.password_verify("my_password", stored)

    nextssl.cleanup()                       # optional — frees internal state

See https://github.com/QudsLab/NextSSL for the full C library documentation.
"""

from ._api import (
    # Info
    version,
    variant,
    security_level,
    # Lifecycle
    init,
    cleanup,
    selftest,
    # Core crypto
    random_bytes,
    hash,
    encrypt,
    decrypt,
    derive_key,
    # Password
    password_hash,
    password_verify,
    # Utilities
    secure_zero,
    constant_compare,
    # Errors
    NextSSLError,
)

__version__: str = "0.0.1"

__all__ = [
    "version",
    "variant",
    "security_level",
    "init",
    "cleanup",
    "selftest",
    "random_bytes",
    "hash",
    "encrypt",
    "decrypt",
    "derive_key",
    "password_hash",
    "password_verify",
    "secure_zero",
    "constant_compare",
    "NextSSLError",
]
