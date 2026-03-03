"""ctypes function bindings and Python-friendly wrappers for the NextSSL C API."""
from __future__ import annotations

import ctypes
from ctypes import c_int, c_size_t, c_char_p, c_void_p, POINTER
from typing import Optional

from ._loader import lib

# ── ctypes helpers ────────────────────────────────────────────────────────────

_c_uint8_p = ctypes.POINTER(ctypes.c_uint8)


class NextSSLError(Exception):
    """Raised when a NextSSL C function returns a negative error code."""

    _NAMES = {
        -1:  "ERR_NOT_INIT",
        -2:  "ERR_ALREADY_INIT",
        -3:  "ERR_INVALID_PROF",
        -4:  "ERR_ALGO_UNAVAIL",
        -5:  "ERR_ALGO_BLOCKED",
        -35: "ARGON2_VERIFY_MISMATCH",
    }

    def __init__(self, fn: str, code: int) -> None:
        self.code = code
        name = self._NAMES.get(code, f"ERR_{abs(code)}")
        super().__init__(f"{fn} failed with {name} (code {code})")


# ── Function signatures ───────────────────────────────────────────────────────

# version / variant / security_level
lib.nextssl_version.restype          = c_char_p
lib.nextssl_version.argtypes         = []
lib.nextssl_variant.restype          = c_char_p
lib.nextssl_variant.argtypes         = []
lib.nextssl_security_level.restype   = c_char_p
lib.nextssl_security_level.argtypes  = []

# init / cleanup / selftest
lib.nextssl_init.restype             = c_int
lib.nextssl_init.argtypes            = [c_int]
lib.nextssl_cleanup.restype          = None
lib.nextssl_cleanup.argtypes         = []
lib.nextssl_selftest.restype         = c_int
lib.nextssl_selftest.argtypes        = []

# random
lib.nextssl_random.restype           = c_int
lib.nextssl_random.argtypes          = [_c_uint8_p, c_size_t]

# hash
lib.nextssl_hash.restype             = c_int
lib.nextssl_hash.argtypes            = [_c_uint8_p, c_size_t, _c_uint8_p]

# encrypt / decrypt
lib.nextssl_encrypt.restype          = c_int
lib.nextssl_encrypt.argtypes         = [_c_uint8_p, _c_uint8_p, c_size_t,
                                        _c_uint8_p, POINTER(c_size_t)]
lib.nextssl_decrypt.restype          = c_int
lib.nextssl_decrypt.argtypes         = [_c_uint8_p, _c_uint8_p, c_size_t,
                                        _c_uint8_p, POINTER(c_size_t)]

# derive_key
lib.nextssl_derive_key.restype       = c_int
lib.nextssl_derive_key.argtypes      = [_c_uint8_p, c_size_t, c_char_p,
                                        _c_uint8_p, c_size_t]

# password_hash / verify
lib.nextssl_password_hash.restype    = c_int
lib.nextssl_password_hash.argtypes   = [c_char_p, c_size_t, c_char_p, c_size_t]
lib.nextssl_password_verify.restype  = c_int
lib.nextssl_password_verify.argtypes = [c_char_p, c_size_t, c_char_p]

# secure_zero / constant_compare
lib.nextssl_secure_zero.restype        = None
lib.nextssl_secure_zero.argtypes       = [c_void_p, c_size_t]
lib.nextssl_constant_compare.restype   = c_int
lib.nextssl_constant_compare.argtypes  = [c_void_p, c_void_p, c_size_t]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _as_u8p(data: bytes) -> ctypes.POINTER:
    return ctypes.cast(ctypes.c_char_p(data), _c_uint8_p)


def _buf(n: int) -> ctypes.Array:
    return ctypes.create_string_buffer(n)


# ── Public API ────────────────────────────────────────────────────────────────

def version() -> str:
    """Return the NextSSL version string (e.g. ``'0.0.1-beta'``)."""
    return lib.nextssl_version().decode()


def variant() -> str:
    """Return ``'full'`` or ``'lite'`` depending on the build."""
    return lib.nextssl_variant().decode()


def security_level() -> str:
    """Return the active security-level string (e.g. ``'modern-safe'``)."""
    return lib.nextssl_security_level().decode()


def init(profile: int = 0) -> None:
    """
    Initialize NextSSL with a security profile.

    Profiles:
        0 = MODERN (default) — SHA-256, AES-256-GCM, Ed25519, X25519
        1 = COMPLIANCE        — FIPS/NIST aligned
        2 = PQC               — Post-quantum
        3 = COMPATIBILITY     — Includes legacy-alive algorithms
        4 = EMBEDDED          — ChaCha20-Poly1305, small footprint
        5 = RESEARCH          — All algorithms including unsafe

    ``init()`` is called automatically on the first library use if you omit it.
    Calling it twice raises ``NextSSLError(code=-2)``.
    """
    rc = lib.nextssl_init(profile)
    if rc < 0:
        raise NextSSLError("nextssl_init", rc)


def cleanup() -> None:
    """Release NextSSL resources."""
    lib.nextssl_cleanup()


def selftest() -> int:
    """
    Run comprehensive self-tests.

    Returns ``0`` if all tests pass.  Raises ``NextSSLError`` on failure.
    """
    rc = lib.nextssl_selftest()
    if rc < 0:
        raise NextSSLError("nextssl_selftest", rc)
    return rc


def random_bytes(length: int) -> bytes:
    """
    Generate *length* cryptographically secure random bytes.

    >>> key = random_bytes(32)
    >>> len(key)
    32
    """
    if length <= 0:
        raise ValueError("length must be a positive integer")
    buf = _buf(length)
    rc = lib.nextssl_random(ctypes.cast(buf, _c_uint8_p), c_size_t(length))
    if rc < 0:
        raise NextSSLError("nextssl_random", rc)
    return buf.raw


def hash(data: bytes) -> bytes:
    """
    SHA-256 hash of *data*.

    Returns 32 bytes.

    >>> import hashlib
    >>> hash(b"hello") == hashlib.sha256(b"hello").digest()
    True
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    out = _buf(32)
    rc = lib.nextssl_hash(_as_u8p(bytes(data)), c_size_t(len(data)),
                          ctypes.cast(out, _c_uint8_p))
    if rc < 0:
        raise NextSSLError("nextssl_hash", rc)
    return out.raw


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM (automatic nonce generation).

    *key* must be exactly 32 bytes.

    The returned ciphertext layout is::

        [12-byte nonce][ciphertext bytes][16-byte auth tag]

    Total length: ``len(plaintext) + 28``.

    >>> key = random_bytes(32)
    >>> ct = encrypt(key, b"secret")
    >>> len(ct) == len(b"secret") + 28
    True
    """
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    ct_len = c_size_t(0)
    ct_buf = _buf(len(plaintext) + 28)
    rc = lib.nextssl_encrypt(
        _as_u8p(key),
        _as_u8p(bytes(plaintext)), c_size_t(len(plaintext)),
        ctypes.cast(ct_buf, _c_uint8_p),
        ctypes.byref(ct_len),
    )
    if rc < 0:
        raise NextSSLError("nextssl_encrypt", rc)
    return ct_buf.raw[: ct_len.value]


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt *ciphertext* produced by :func:`encrypt`.

    *key* must be exactly 32 bytes.
    Raises ``NextSSLError`` on authentication failure or wrong key.

    >>> key = random_bytes(32)
    >>> decrypt(key, encrypt(key, b"hello")) == b"hello"
    True
    """
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    pt_len = c_size_t(0)
    pt_buf = _buf(len(ciphertext))
    rc = lib.nextssl_decrypt(
        _as_u8p(key),
        _as_u8p(bytes(ciphertext)), c_size_t(len(ciphertext)),
        ctypes.cast(pt_buf, _c_uint8_p),
        ctypes.byref(pt_len),
    )
    if rc < 0:
        raise NextSSLError("nextssl_decrypt", rc)
    return pt_buf.raw[: pt_len.value]


def derive_key(
    input_material: bytes,
    length: int,
    context: Optional[str] = None,
) -> bytes:
    """
    Derive *length* bytes of key material from *input_material* using HKDF-SHA256.

    *context* is an optional ASCII label for domain separation.

    >>> k1 = derive_key(b"seed", 32, context="app-v1")
    >>> k2 = derive_key(b"seed", 32, context="app-v1")
    >>> k1 == k2
    True
    """
    if length <= 0:
        raise ValueError("length must be positive")
    out = _buf(length)
    ctx = context.encode() if context else None
    rc = lib.nextssl_derive_key(
        _as_u8p(bytes(input_material)), c_size_t(len(input_material)),
        ctx,
        ctypes.cast(out, _c_uint8_p), c_size_t(length),
    )
    if rc < 0:
        raise NextSSLError("nextssl_derive_key", rc)
    return out.raw


def password_hash(password: "str | bytes", buffer_size: int = 256) -> str:
    """
    Hash *password* for storage using Argon2id.

    Returns an encoded hash string.  Pass it directly to :func:`password_verify`.

    >>> h = password_hash("hunter2")
    >>> password_verify("hunter2", h)
    True
    """
    if isinstance(password, str):
        password = password.encode()
    out = _buf(buffer_size)
    rc = lib.nextssl_password_hash(
        password, c_size_t(len(password)),
        out, c_size_t(buffer_size),
    )
    if rc < 0:
        raise NextSSLError("nextssl_password_hash", rc)
    return out.value.decode()


def password_verify(password: "str | bytes", stored_hash: str) -> bool:
    """
    Verify *password* against a hash produced by :func:`password_hash`.

    Returns ``True`` on match, ``False`` on mismatch.
    Uses constant-time comparison internally.

    Internally ``argon2id_verify`` returns 0 (ARGON2_OK) on match and
    -35 (ARGON2_VERIFY_MISMATCH) on mismatch — both are normal outcomes.
    Any other negative code is raised as ``NextSSLError``.
    """
    if isinstance(password, str):
        password = password.encode()
    rc = lib.nextssl_password_verify(
        password, c_size_t(len(password)),
        stored_hash.encode(),
    )
    if rc == 0:    # ARGON2_OK  → password matches
        return True
    if rc == -35:  # ARGON2_VERIFY_MISMATCH → valid "no match" result
        return False
    raise NextSSLError("nextssl_password_verify", rc)


def secure_zero(data: bytearray) -> None:
    """
    Securely zero *data* (a ``bytearray``) in place.

    Unlike ``data[:] = b'\\x00' * len(data)``, this call is not optimised away
    by the compiler.
    """
    if not isinstance(data, bytearray):
        raise TypeError("data must be a bytearray (mutable buffer)")
    addr = ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data))
    lib.nextssl_secure_zero(ctypes.c_void_p(addr), c_size_t(len(data)))


def constant_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison.

    Returns ``True`` if *a* and *b* are equal, ``False`` otherwise.
    Always takes the same time regardless of where bytes differ.

    Different-length inputs always return ``False`` without a library call.
    """
    if len(a) != len(b):
        return False
    rc = lib.nextssl_constant_compare(
        ctypes.cast(ctypes.c_char_p(a), c_void_p),
        ctypes.cast(ctypes.c_char_p(b), c_void_p),
        c_size_t(len(a)),
    )
    return rc == 1
