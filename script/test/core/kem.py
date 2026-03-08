"""script/test/core/kem.py — reusable KEM round-trip runner."""
import ctypes
from .result import Results


def run_kem(
    lib,
    name:              str,
    pk_size:           int,
    sk_size:           int,
    ct_size:           int,
    ss_size:           int,
    keypair_fn:        str,
    keypair_derand_fn: str,
    encaps_fn:         str,
    encaps_derand_fn:  str,
    decaps_fn:         str,
    results:           Results,
) -> None:
    """
    Five sub-tests:
      1. keypair (OS random) — buffers non-zero
      2. keypair_derand (fixed 32-byte seed) — same seed → same output
      3. encaps → decaps — shared secrets match
      4. encaps_derand (fixed 32-byte seed) — deterministic ciphertext
      5. decaps with all-zero ciphertext — shared secret does NOT match (negative)
    """
    # ── Wire signatures ────────────────────────────────────────────────────
    kp = getattr(lib, keypair_fn)
    kp.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    kp.restype  = ctypes.c_int

    kp_d = getattr(lib, keypair_derand_fn)
    kp_d.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    kp_d.restype  = ctypes.c_int

    enc = getattr(lib, encaps_fn)
    enc.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    enc.restype  = ctypes.c_int

    enc_d = getattr(lib, encaps_derand_fn)
    enc_d.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    enc_d.restype  = ctypes.c_int

    dec = getattr(lib, decaps_fn)
    dec.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    dec.restype  = ctypes.c_int

    # ── 1. OS random keypair ───────────────────────────────────────────────
    pk = ctypes.create_string_buffer(pk_size)
    sk = ctypes.create_string_buffer(sk_size)
    ret = kp(pk, sk)
    if ret == 0 and any(pk.raw) and any(sk.raw):
        results.ok(f"{name}: keypair (random)")
    else:
        results.fail(f"{name}: keypair (random)", reason=f"ret={ret}")
        return  # no valid keys — abort remaining sub-tests

    # ── 2. Deterministic keypair ───────────────────────────────────────────
    seed  = b'\x42' * 32
    pk2a  = ctypes.create_string_buffer(pk_size)
    sk2a  = ctypes.create_string_buffer(sk_size)
    pk2b  = ctypes.create_string_buffer(pk_size)
    sk2b  = ctypes.create_string_buffer(sk_size)
    r1    = kp_d(pk2a, sk2a, seed)
    r2    = kp_d(pk2b, sk2b, seed)
    if r1 == 0 and r2 == 0 and pk2a.raw == pk2b.raw and sk2a.raw == sk2b.raw:
        results.ok(f"{name}: keypair_derand (deterministic)")
    else:
        results.fail(f"{name}: keypair_derand (deterministic)",
                     reason=f"r1={r1} r2={r2} pk_match={pk2a.raw==pk2b.raw}")

    # ── 3. encaps → decaps: shared secrets match ───────────────────────────
    ct     = ctypes.create_string_buffer(ct_size)
    ss_enc = ctypes.create_string_buffer(ss_size)
    ss_dec = ctypes.create_string_buffer(ss_size)
    r = enc(ct, ss_enc, pk)
    if r != 0:
        results.fail(f"{name}: encaps", reason=f"ret={r}")
        return
    r = dec(ss_dec, ct, sk)
    if r == 0 and ss_enc.raw == ss_dec.raw:
        results.ok(f"{name}: encaps/decaps (ss match)")
    else:
        results.fail(f"{name}: encaps/decaps (ss match)",
                     reason=f"ret={r} match={ss_enc.raw==ss_dec.raw}")

    # ── 4. Deterministic encaps ─────────────────────────────────────────────
    enc_seed = b'\xAB' * 32
    ct_d1    = ctypes.create_string_buffer(ct_size)
    ss_d1    = ctypes.create_string_buffer(ss_size)
    ct_d2    = ctypes.create_string_buffer(ct_size)
    ss_d2    = ctypes.create_string_buffer(ss_size)
    r1 = enc_d(ct_d1, ss_d1, pk, enc_seed)
    r2 = enc_d(ct_d2, ss_d2, pk, enc_seed)
    if r1 == 0 and r2 == 0 and ct_d1.raw == ct_d2.raw:
        results.ok(f"{name}: encaps_derand (deterministic)")
    else:
        results.fail(f"{name}: encaps_derand (deterministic)",
                     reason=f"r1={r1} r2={r2} ct_match={ct_d1.raw==ct_d2.raw}")

    # ── 5. Negative: wrong ciphertext → shared secret differs ───────────────
    bad_ct  = ctypes.create_string_buffer(ct_size)  # all-zero = invalid
    ss_bad  = ctypes.create_string_buffer(ss_size)
    dec(ss_bad, bad_ct, sk)
    if ss_bad.raw != ss_enc.raw:
        results.ok(f"{name}: decaps wrong ct (negative)")
    else:
        results.fail(f"{name}: decaps wrong ct (negative)",
                     reason="all-zero ciphertext produced matching shared secret")
