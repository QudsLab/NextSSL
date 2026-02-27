"""Shared test infrastructure - logger, vectors, constants."""

import pathlib
import datetime
import sys

# Paths
_THIS_DIR = pathlib.Path(__file__).resolve().parent
TESTS_DIR = _THIS_DIR.parent
REPO_ROOT = TESTS_DIR.parent
LOG_DIR = REPO_ROOT / "logs" / "test"


class TestLogger:
    """Dual stdout + file logger (like bin generator logs)."""
    
    def __init__(self, name, subdir=""):
        """
        name: Module name (e.g., "test_primitive_fast")
        subdir: Subdirectory path (e.g., "hash" or "pow/client")
        """
        self.name = name
        self.passed = 0
        self.failed = 0
        
        # Create log directory matching binary structure
        if subdir:
            log_path = LOG_DIR / subdir
        else:
            log_path = LOG_DIR
        
        log_path.mkdir(parents=True, exist_ok=True)
        self.log_file = log_path / f"{name}.log"
        self.file = open(self.log_file, "w", encoding="utf-8")
        
        self._write_header()
    
    def _write_header(self):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self._out("=" * 70)
        self._out(f"{self.name}.log")
        self._out(ts)
        self._out("=" * 70)
    
    def _out(self, line):
        """Write to both stdout and file."""
        print(line)
        self.file.write(line + "\n")
        self.file.flush()
    
    def section(self, title):
        """Print section header."""
        self._out(f"\n{'='*70}")
        self._out(f"  {title}")
        self._out("=" * 70)
    
    def pass_(self, name, **details):
        """Log a passing test."""
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        self._out(f"[PASS] {name:<50} {detail_str}")
        self.passed += 1
    
    def fail(self, name, **details):
        """Log a failing test."""
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        self._out(f"[FAIL] {name:<50} {detail_str}")
        self.failed += 1
    
    def info(self, msg):
        """Log informational message."""
        self._out(f"[INFO] {msg}")
    
    def data(self, label, hex_data, max_len=64):
        """Log hex data (like bin generator)."""
        if isinstance(hex_data, bytes):
            hex_data = hex_data.hex()
        if len(hex_data) > max_len * 2:
            display = hex_data[:max_len*2] + "..."
        else:
            display = hex_data
        self._out(f"       {label}: {display}")
    
    def summary(self):
        """Write summary and return (passed, failed)."""
        total = self.passed + self.failed
        status = "PASS" if self.failed == 0 else "FAIL"
        
        self._out("\n" + "=" * 70)
        self._out("SUMMARY")
        self._out("=" * 70)
        self._out(f"Passed:  {self.passed}")
        self._out(f"Failed:  {self.failed}")
        self._out(f"Total:   {total}")
        self._out(f"Status:  {status}")
        self._out("=" * 70)
        
        self.file.close()
        return self.passed, self.failed


# Known test vectors from NIST, RFC, and existing tests
VECTORS = {
    "SHA256": {
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "SHA512": {
        b"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        b"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
             "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    "SHA224": {
        b"abc": "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    },
    "SHA384": {
        b"abc": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
               "8086072ba1e7cc2358baeca134c825a7",
    },
    "MD5": {
        b"abc": "900150983cd24fb0d6963f7d28e17f72",
        b"": "d41d8cd98f00b204e9800998ecf8427e",
    },
    "SHA1": {
        b"abc": "a9993e364706816aba3e25717850c26c9cd0d89d",
        b"": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    },
    "BLAKE2B": {
        b"abc": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
               "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    },
    "BLAKE2S": {
        b"abc": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    },
}
