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
    decrypt_ct_len: int = None,
) -> None:
    """Encrypt then decrypt; verify plaintext is recovered and tag passes.

    decrypt_ct_len overrides the ciphertext-length argument passed to the
    decrypt function.  Most AEAD modes (GCM, CCM, OCB, EAX, GCM-SIV) pass
    only the plaintext length; ChaCha20-Poly1305 expects the combined
    ciphertext+tag length (pt_len + 16), so callers set decrypt_ct_len
    accordingly.
    """
    enc = getattr(lib, encrypt_fn)
    enc.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p,  # ciphertext || tag output
    ]
    enc.restype = None

    dec = getattr(lib, decrypt_fn)
    dec.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p,  # plaintext output
    ]
    dec.restype = ctypes.c_int

    pt_len = len(plaintext)
    ct_buf = ctypes.create_string_buffer(pt_len + 16)
    enc(key, nonce, aad or b"", len(aad), plaintext or b"", pt_len, ct_buf)

    pt_buf = ctypes.create_string_buffer(max(pt_len, 1))
    ct_len_for_dec = decrypt_ct_len if decrypt_ct_len is not None else pt_len
    ret = dec(key, nonce, aad or b"", len(aad), ct_buf.raw, ct_len_for_dec, pt_buf)
    if ret == 0 and pt_buf.raw[:pt_len] == plaintext:
        results.ok(f"{name} AEAD round-trip")
    else:
        results.fail(f"{name} AEAD round-trip",
                     reason=f"decrypt ret={ret}")
