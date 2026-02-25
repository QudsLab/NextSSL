"""Shared test infrastructure - logger, vectors, constants, binary detection."""

import hashlib
import pathlib
import sys
import datetime


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# common.py lives at {repo}/libs/python/tests/utils/common.py
_THIS_DIR = pathlib.Path(__file__).resolve().parent          # utils/
_TESTS_DIR = _THIS_DIR.parent                                # tests/
REPO_ROOT = _TESTS_DIR.parent.parent.parent                  # repo root
LOG_DIR = REPO_ROOT / "logs" / "test"
SRC_DIR = REPO_ROOT / "libs" / "python" / "src"


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class TestLogger:
    """Dual stdout + file logger with pass/fail tracking."""

    def __init__(self, name):
        self.name = name
        self.passed = 0
        self.failed = 0

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._file = open(LOG_DIR / f"{name}.log", "w", encoding="utf-8")
        self._write_header()

    def _write_header(self):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self._out("=" * 55)
        self._out(self.name + ".log")
        self._out(ts)
        self._out("=" * 55)

    def _out(self, line):
        print(line)
        self._file.write(line + "\n")
        self._file.flush()

    def section(self, title):
        self._out(f"\n=== {title} ===")

    def check(self, condition, name, **details):
        """Log a pass/fail check. No try/except - crashes propagate."""
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        if condition:
            self.passed += 1
            self._out(f"[PASS] {name:<45} {detail_str}")
        else:
            self.failed += 1
            self._out(f"[FAIL] {name:<45} {detail_str}")

    def info(self, msg):
        self._out(f"[INFO] {msg}")

    def summary(self):
        total = self.passed + self.failed
        status = "PASS" if self.failed == 0 else "FAIL"
        lines = [
            "",
            "--- SUMMARY ---",
            f"Passed: {self.passed}",
            f"Failed: {self.failed}",
            f"Total:  {total}",
            f"Status: {status}",
        ]
        for line in lines:
            self._out(line)
        self._file.close()
        return self.passed, self.failed

    def close(self):
        if not self._file.closed:
            self._file.close()


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

_BINARIES_CHECKED = None


def has_binaries():
    """Check if NextSSL C binaries are available. Cached after first call."""
    global _BINARIES_CHECKED
    if _BINARIES_CHECKED is not None:
        return _BINARIES_CHECKED

    ensure_importable()

    from nextssl._loader import find_bin_directory
    bin_dir = find_bin_directory()
    if bin_dir is None:
        _BINARIES_CHECKED = False
        return False

    # Check if the system library actually exists
    from nextssl._loader import get_platform_info
    _, ext = get_platform_info()
    system_lib = bin_dir / "main" / f"system{ext}"
    _BINARIES_CHECKED = system_lib.exists()
    return _BINARIES_CHECKED


def ensure_importable():
    """Make sure nextssl is importable."""
    src = str(SRC_DIR)
    if src not in sys.path:
        sys.path.insert(0, src)


# ---------------------------------------------------------------------------
# Known Answer Tests (KAT vectors)
# ---------------------------------------------------------------------------

VECTORS = {
    "SHA224": {
        b"": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    },
    "SHA256": {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"nextssl": None,  # computed at load time below
    },
    "SHA384": {
        b"": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    "SHA512": {
        b"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    "MD5": {
        b"": "d41d8cd98f00b204e9800998ecf8427e",
        b"nextssl": None,
    },
    "SHA1": {
        b"": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        b"nextssl": None,
    },
    "MD2": {
        b"": "8350e5a3e24c153df2275c9f80692773",
    },
    "MD4": {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
    },
}

# Pre-compute vectors we can verify with Python stdlib
VECTORS["SHA256"][b"nextssl"] = hashlib.sha256(b"nextssl").hexdigest()
VECTORS["MD5"][b"nextssl"] = hashlib.md5(b"nextssl").hexdigest()
VECTORS["SHA1"][b"nextssl"] = hashlib.sha1(b"nextssl").hexdigest()


# ---------------------------------------------------------------------------
# Test data constants
# ---------------------------------------------------------------------------

TEST_DATA_EMPTY = b""
TEST_DATA_SHORT = b"nextssl"
TEST_DATA_BLOCK = b"A" * 64
TEST_DATA_MULTI = b"B" * 1024

TEST_KEY_128 = bytes(16)
TEST_KEY_192 = bytes(24)
TEST_KEY_256 = bytes(32)
TEST_NONCE_12 = bytes(12)
TEST_NONCE_24 = bytes(24)
TEST_SALT_16 = bytes(16)
TEST_DRBG_SEED = bytes(48)
TEST_SIPHASH_KEY = bytes(16)
TEST_MESSAGE = b"The quick brown fox jumps over the lazy dog"
