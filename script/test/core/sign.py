"""script/test/core/sign.py — reusable sign/verify round-trip runner."""
import ctypes
from .result import Results


def run_sign(
    lib,
    name:              str,
    pk_size:           int,
    sk_size:           int,
    max_sig_size:      int,
    keypair_fn:        str,
    keypair_derand_fn: str,
    sign_fn:           str,
    sign_derand_fn:    str,
    verify_fn:         str,
    results:           Results,
    mldsa:             bool = False,
) -> None:
    """
    Six sub-tests:
      1. keypair (OS random)
      2. keypair_derand (fixed seed) — deterministic
      3. sign message → verify — must accept
      4. sign_derand (fixed seed) — deterministic signature
      5. verify with tampered message — must reject  (negative)
      6. verify with tampered signature — must reject (negative)

    Set mldsa=True for ML-DSA whose sign_derand takes an extra context param.
    """
    # ── Wire signatures ────────────────────────────────────────────────────
    kp = getattr(lib, keypair_fn)
    kp.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    kp.restype  = ctypes.c_int

    kp_d = getattr(lib, keypair_derand_fn)
    kp_d.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    kp_d.restype  = ctypes.c_int

    sign = getattr(lib, sign_fn)
    sign.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    sign.restype = ctypes.c_int

    sign_d = getattr(lib, sign_derand_fn)
    if mldsa:
        # ML-DSA sign_derand: (sig, siglen, msg, msglen, ctx, ctxlen, rnd, sk)
        sign_d.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
    else:
        # Falcon / SPHINCS+: (sig, siglen, msg, msglen, rnd, sk)
        sign_d.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
    sign_d.restype = ctypes.c_int

    ver = getattr(lib, verify_fn)
    ver.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    ver.restype = ctypes.c_int

    # ── 1. OS random keypair ───────────────────────────────────────────────
    pk  = ctypes.create_string_buffer(pk_size)
    sk  = ctypes.create_string_buffer(sk_size)
    ret = kp(pk, sk)
    if ret == 0 and any(pk.raw):
        results.ok(f"{name}: keypair (random)")
    else:
        results.fail(f"{name}: keypair (random)", reason=f"ret={ret}")
        return

    # ── 2. Deterministic keypair ───────────────────────────────────────────
    seed = b'\x42' * 32
    pk2a = ctypes.create_string_buffer(pk_size)
    sk2a = ctypes.create_string_buffer(sk_size)
    pk2b = ctypes.create_string_buffer(pk_size)
    sk2b = ctypes.create_string_buffer(sk_size)
    r1   = kp_d(pk2a, sk2a, seed)
    r2   = kp_d(pk2b, sk2b, seed)
    if r1 == 0 and r2 == 0 and pk2a.raw == pk2b.raw:
        results.ok(f"{name}: keypair_derand (deterministic)")
    else:
        results.fail(f"{name}: keypair_derand (deterministic)",
                     reason=f"r1={r1} r2={r2} match={pk2a.raw==pk2b.raw}")

    # ── 3. sign → verify ──────────────────────────────────────────────────
    msg    = b"NextSSL sign/verify round-trip test message"
    sig    = ctypes.create_string_buffer(max_sig_size)
    siglen = ctypes.c_size_t(0)
    ret    = sign(sig, ctypes.byref(siglen), msg, len(msg), sk)
    if ret != 0:
        results.fail(f"{name}: sign", reason=f"ret={ret}")
        return
    results.ok(f"{name}: sign")

    ret = ver(sig, siglen, msg, len(msg), pk)
    if ret == 0:
        results.ok(f"{name}: verify (valid)")
    else:
        results.fail(f"{name}: verify (valid)", reason=f"ret={ret}")

    # ── 4. sign_derand — deterministic ────────────────────────────────────
    rnd    = b'\x77' * 32
    sig_d1 = ctypes.create_string_buffer(max_sig_size)
    slen1  = ctypes.c_size_t(0)
    sig_d2 = ctypes.create_string_buffer(max_sig_size)
    slen2  = ctypes.c_size_t(0)
    if mldsa:
        r1 = sign_d(sig_d1, ctypes.byref(slen1), msg, len(msg), b"", 0, rnd, sk)
        r2 = sign_d(sig_d2, ctypes.byref(slen2), msg, len(msg), b"", 0, rnd, sk)
    else:
        r1 = sign_d(sig_d1, ctypes.byref(slen1), msg, len(msg), sk, rnd)
        r2 = sign_d(sig_d2, ctypes.byref(slen2), msg, len(msg), sk, rnd)
    match = sig_d1.raw[:slen1.value] == sig_d2.raw[:slen2.value]
    if r1 == 0 and r2 == 0 and match:
        results.ok(f"{name}: sign_derand (deterministic)")
    else:
        results.fail(f"{name}: sign_derand (deterministic)",
                     reason=f"r1={r1} r2={r2} sig_match={match}")

    # ── 5. Negative: tampered message ─────────────────────────────────────
    bad_msg = bytearray(msg)
    bad_msg[0] ^= 0xFF
    ret = ver(sig, siglen, bytes(bad_msg), len(msg), pk)
    if ret != 0:
        results.ok(f"{name}: verify tampered msg (negative)")
    else:
        results.fail(f"{name}: verify tampered msg (negative)",
                     reason="tampered message accepted as valid")

    # ── 6. Negative: tampered signature ───────────────────────────────────
    bad_sig_data = bytearray(sig.raw[:siglen.value])
    bad_sig_data[0] ^= 0xFF
    bad_sig = ctypes.create_string_buffer(
        bytes(bad_sig_data) + b'\x00' * (max_sig_size - siglen.value)
    )
    ret = ver(bad_sig, siglen, msg, len(msg), pk)
    if ret != 0:
        results.ok(f"{name}: verify tampered sig (negative)")
    else:
        results.fail(f"{name}: verify tampered sig (negative)",
                     reason="tampered signature accepted as valid")
