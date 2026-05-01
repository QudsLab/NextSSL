"""Minimal smoke KAT: SHA-256("abc") via ctypes.

Uses Python's own ``hashlib`` as the reference so there is no hardcoded hex
value that could go stale.  A single ctypes call to
``nextssl_hash_compute("sha256", "abc")`` is enough to confirm:
  - the library loads correctly
  - the symbol is exported
  - the computation is correct on this architecture / byte-order

Skipped automatically for WASM variants (js-glue / wasi .wasm) and for
header-only variants (pe_check / macho_check).
"""
from __future__ import annotations

import ctypes
import hashlib
import sys
from pathlib import Path
from typing import Tuple

# Reference vector – computed by Python stdlib
_INPUT:    bytes = b"abc"
_ALGO:     bytes = b"sha256"
_EXPECTED: bytes = hashlib.sha256(_INPUT).digest()   # 32 bytes
_BUFLEN:   int   = 64   # output buffer (over-allocated)

# Modes that cannot load a native shared library
_SKIP_MODES: frozenset[str] = frozenset({
    "pe_check", "macho_check", "node_wasm", "wasi_wasm",
})


def run(lib_path: "str | Path", exec_mode: str) -> Tuple[bool, str]:
    """Run the SHA-256 smoke KAT against the native shared library.

    Parameters
    ----------
    lib_path:  path to the .dll / .so / .dylib
    exec_mode: Variant.exec_mode

    Returns
    -------
    (ok, message)
    """
    if exec_mode in _SKIP_MODES:
        return True, f"SKIP smoke KAT (exec_mode={exec_mode})"

    p = Path(lib_path)
    try:
        lib = ctypes.CDLL(str(p))
    except OSError as exc:
        return False, f"cannot load library: {exc}"

    try:
        fn = lib.nextssl_hash_compute
        fn.argtypes = [
            ctypes.c_char_p,   # algo name (NUL-terminated)
            ctypes.c_void_p,   # input buffer
            ctypes.c_size_t,   # input length
            ctypes.c_void_p,   # output buffer
            ctypes.c_size_t,   # output buffer capacity
        ]
        fn.restype = ctypes.c_int
    except AttributeError:
        return False, "symbol nextssl_hash_compute not found"

    out = (ctypes.c_uint8 * _BUFLEN)()
    rc = fn(_ALGO, _INPUT, len(_INPUT), out, _BUFLEN)
    if rc < 0:
        return False, f"nextssl_hash_compute returned {rc}"

    actual = bytes(out[: len(_EXPECTED)])
    if actual != _EXPECTED:
        return False, (
            f"SHA-256 mismatch\n"
            f"  expected: {_EXPECTED.hex()}\n"
            f"  got:      {actual.hex()}"
        )

    return True, f"SHA-256 KAT OK  ({_INPUT!r} → {_EXPECTED.hex()[:16]}…)"
