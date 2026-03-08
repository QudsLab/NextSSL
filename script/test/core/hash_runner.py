"""script/test/core/hash_runner.py — simple-hash KAT and streaming runners."""
import ctypes
from .result import Results


def run_hash_kat(
    lib,
    fn_name:      str,
    data:         bytes,
    expected_hex: str,
    out_size:     int,
    results:      Results,
) -> None:
    """Call lib.<fn_name>(data, len(data), out); compare hex digest.

    Assumes the standard (data, len, out) triple — covers SHA-2, SHA-3,
    BLAKE3/2, Keccak, SHAKE (fixed-length), SHA-1, MD5/MD2/MD4.
    """
    fn = getattr(lib, fn_name)
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    fn.restype  = None
    out = ctypes.create_string_buffer(out_size)
    fn(data, len(data), out)
    if out.raw.hex() == expected_hex:
        results.ok(f"{fn_name} KAT")
    else:
        results.fail(
            f"{fn_name} KAT",
            reason=f"got {out.raw.hex()[:32]}… expected {expected_hex[:32]}…",
        )


def run_hash_streaming(
    lib,
    init_fn:      str,
    update_fn:    str,
    final_fn:     str,
    data:         bytes,
    expected_hex: str,
    ctx_size:     int,
    out_size:     int,
    results:      Results,
    name:         str,
) -> None:
    """Test streaming hash API: init → update → final → compare digest."""
    init_f   = getattr(lib, init_fn)
    update_f = getattr(lib, update_fn)
    final_f  = getattr(lib, final_fn)

    ctx = ctypes.create_string_buffer(ctx_size)
    init_f.argtypes   = [ctypes.c_char_p]
    init_f.restype    = None
    update_f.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    update_f.restype  = None
    final_f.argtypes  = [ctypes.c_char_p, ctypes.c_char_p]
    final_f.restype   = None

    out = ctypes.create_string_buffer(out_size)
    init_f(ctx)
    update_f(ctx, data, len(data))
    final_f(ctx, out)

    if out.raw.hex() == expected_hex:
        results.ok(f"{name} streaming KAT")
    else:
        results.fail(
            f"{name} streaming KAT",
            reason=f"got {out.raw.hex()[:32]}… expected {expected_hex[:32]}…",
        )
