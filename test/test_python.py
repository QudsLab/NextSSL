"""test_python.py — meta / integration suite for the nextssl Python bindings.

This file serves two purposes:

1.  **pytest discovery target** — run from the project root:

        pytest test/                      # all tests (this file + test/python/)
        pytest test/test_python.py        # integration + meta tests only
        pytest test/python/               # per-domain unit tests only

2.  **Standalone runner** — invoke directly to run the full test suite:

        python test/test_python.py        # runs pytest on itself + test/python/
        python test/test_python.py -x     # stop on first failure
        python test/test_python.py -v     # verbose

Meta tests in this file verify:
  - The nextssl package is importable and all public API symbols are present
  - The __version__ attribute matches the version string returned by the C lib
  - An end-to-end crypto flow executes without error

"""
from __future__ import annotations

import hashlib
import os
import sys

import pytest

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Allows running tests from the project root without installing the package;
# the conftest.py in test/ already handles this for pytest runs, but we repeat
# it here so `python test/test_python.py` also works.

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.abspath(os.path.join(_HERE, "..", "libs", "python", "src"))
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import nextssl  # noqa: E402


# ── Expected public API surface ───────────────────────────────────────────────

_EXPECTED_SYMBOLS = [
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


# ── Meta tests ────────────────────────────────────────────────────────────────

class TestImport:
    """Verify the package is importable and exposes the expected API surface."""

    def test_import_succeeds(self):
        import nextssl as _ns  # noqa: F401

    def test_version_attribute_exists(self):
        assert hasattr(nextssl, "__version__")

    def test_version_attribute_is_string(self):
        assert isinstance(nextssl.__version__, str)

    @pytest.mark.parametrize("sym", _EXPECTED_SYMBOLS)
    def test_symbol_exported(self, sym: str):
        assert hasattr(nextssl, sym), (
            f"nextssl.{sym} is missing from the public API"
        )

    def test_all_list_complete(self):
        """__all__ must contain every expected symbol."""
        missing = [s for s in _EXPECTED_SYMBOLS if s not in nextssl.__all__]
        assert not missing, f"Symbols missing from __all__: {missing}"


class TestVersionConsistency:
    """Verify that Python-layer __version__ matches the C library version string."""

    def test_versions_match(self):
        """The X.Y.Z part of __version__ must appear in the C library version string.

        The C library may return a decorated string like ``'NextSSL v0.0.1-beta'``
        while the Python package exposes bare ``'0.0.1'``.  We verify that the
        Python semver is contained in the C string rather than requiring an
        exact match.
        """
        import re as _re
        # Allow Python dev suffix (e.g., 0.0.1.dev130) but compare on base X.Y.Z
        py_ver = nextssl.__version__.split(".dev", 1)[0].split("-", 1)[0]
        c_raw  = nextssl.version()
        # Extract the first X.Y.Z sequence from the C version string
        m = _re.search(r'(\d+\.\d+\.\d+)', c_raw)
        assert m is not None, f"No semver found in C version string: {c_raw!r}"
        c_ver = m.group(1)
        assert py_ver == c_ver, (
            f"Python __version__ ({nextssl.__version__!r}) does not match "
            f"C library version ({c_raw!r})"
        )

    def test_version_from_pyproject(self):
        """If pyproject.toml is accessible, its version must match __version__."""
        import re
        pyproject = os.path.join(_HERE, "..", "libs", "python", "pyproject.toml")
        if not os.path.isfile(pyproject):
            pytest.skip("pyproject.toml not found — skipping pyproject version check")
        with open(pyproject, encoding="utf-8") as fh:
            content = fh.read()
        m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
        if not m:
            pytest.skip("version field not found in pyproject.toml")
        assert m.group(1) == nextssl.__version__, (
            f"pyproject.toml version ({m.group(1)!r}) != "
            f"nextssl.__version__ ({nextssl.__version__!r})"
        )


# ── End-to-end integration flow ───────────────────────────────────────────────

class TestEndToEnd:
    """Full crypto pipeline in a single test session.

    Each method is independent; the session fixture below ensures the library
    is in a clean, initialised state before this class runs.
    """

    def test_00_selftest(self):
        assert nextssl.selftest() == 0

    def test_01_random_bytes(self):
        r = nextssl.random_bytes(32)
        assert isinstance(r, bytes) and len(r) == 32

    def test_02_hash_sha256_vector(self):
        expected = hashlib.sha256(b"").digest()
        assert nextssl.hash(b"") == expected

    def test_03_encrypt_decrypt(self):
        key = nextssl.random_bytes(32)
        pt  = b"end-to-end integration test payload"
        assert nextssl.decrypt(key, nextssl.encrypt(key, pt)) == pt

    def test_04_derive_key_domain_separation(self):
        ikm = nextssl.random_bytes(32)
        k1  = nextssl.derive_key(ikm, 32, "enc")
        k2  = nextssl.derive_key(ikm, 32, "mac")
        assert k1 != k2

    def test_05_password_hash_verify(self):
        pw     = "integration test password"
        stored = nextssl.password_hash(pw)
        assert nextssl.password_verify(pw, stored) is True
        assert nextssl.password_verify("wrong", stored) is False

    def test_06_constant_compare(self):
        a = nextssl.random_bytes(32)
        b = nextssl.random_bytes(32)
        assert nextssl.constant_compare(a, a) is True
        assert nextssl.constant_compare(a, b) is False

    def test_07_secure_zero(self):
        buf = bytearray(nextssl.random_bytes(32))
        nextssl.secure_zero(buf)
        assert buf == bytearray(32)

    def test_08_error_type(self):
        """NextSSLError must be a subclass of Exception."""
        assert issubclass(nextssl.NextSSLError, Exception)


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run this file first, then all per-domain tests under test/python/.
    _python_dir = os.path.join(_HERE, "python")
    _args = [__file__, _python_dir, "--tb=short"] + sys.argv[1:]
    sys.exit(pytest.main(_args))
