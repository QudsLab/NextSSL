"""script/test/core/cipher.py — cipher/AEAD KAT and round-trip runners."""
import ctypes
from .result import Results


def run_cipher_kat(
    lib,
    fn_name:       str,
    argtypes:      list,
    call_args:     tuple,
    expected_hex:  str,
    results:       Results,
    out_buf_index: int = -1,
) -> None:
    """Run one known-answer test against a cipher function.

    *call_args* must contain the output buffer at *out_buf_index* (default: last).
    The function is called with the given argtypes and its output is compared
    to *expected_hex*.
    """
    fn = getattr(lib, fn_name)
    fn.argtypes = argtypes
    fn.restype  = None
    fn(*call_args)
    out_buf = call_args[out_buf_index]
    actual  = out_buf.raw.hex() if hasattr(out_buf, 'raw') else bytes(out_buf).hex()
    if actual == expected_hex:
        results.ok(f"{fn_name} KAT")
    else:
        results.fail(f"{fn_name} KAT",
                     reason=f"got {actual[:32]}… expected {expected_hex[:32]}…")


def run_aead_roundtrip(
    lib,
    encrypt_fn: str,
    decrypt_fn: str,
    key:        bytes,
    nonce:      bytes,
    plaintext:  bytes,
    aad:        bytes,
    results:    Results,
    name:       str,
) -> None:
    """Encrypt then decrypt; verify plaintext is recovered and tag passes."""
    enc = getattr(lib, encrypt_fn)
    enc.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p,  # tag output
    ]
    enc.restype = None

    dec = getattr(lib, decrypt_fn)
    dec.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p,  # tag input
    ]
    dec.restype = ctypes.c_int

    pt_len  = max(len(plaintext), 1)
    ct_buf  = ctypes.create_string_buffer(pt_len)
    tag_buf = ctypes.create_string_buffer(16)
    enc(key, nonce, plaintext or b"\x00", len(plaintext), aad or b"", len(aad), tag_buf)

    pt_buf = ctypes.create_string_buffer(pt_len)
    ret    = dec(key, nonce, ct_buf.raw, len(plaintext), aad or b"", len(aad), tag_buf)
    if ret == 0 and pt_buf.raw[:len(plaintext)] == plaintext:
        results.ok(f"{name} AEAD round-trip")
    else:
        results.fail(f"{name} AEAD round-trip",
                     reason=f"decrypt ret={ret}")
