"""
script/web/pqc.py — WASM functional tests for pqc.wasm (main tier).

Covers all exported PQC algorithms:
  KEM  — ML-KEM-512/768/1024, HQC-128/192/256
  Sign — ML-DSA-44/65/87, Falcon-512/1024, Falcon-padded-512/1024,
         SPHINCS+-SHA2 (128f/128s/192f/192s/256f/256s),
         SPHINCS+-SHAKE (128f/128s/192f/192s/256f/256s)

McEliece is intentionally excluded from pqc.wasm (keys up to 1.3 MB —
impractical in a browser context).

Every algorithm is tested with a full round-trip:
  KEM:  keypair → encaps → decaps  (shared secrets must match)
  Sign: keypair → sign → verify    (verify must accept valid sig)

All key/signature buffers are allocated on the WASM heap (not the WASM
64 KB stack) via malloc, so large PQC sizes pose no stack overflow risk.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module


# ─────────────────────────────────────────────────────────────────────────────
# Buffer sizes (bytes) — exact NIST / PQClean values
# ─────────────────────────────────────────────────────────────────────────────

_KEM = {
    # (pk, sk, ct, ss)
    'mlkem512':   ( 800,  1632,  768,  32),
    'mlkem768':   (1184,  2400, 1088,  32),
    'mlkem1024':  (1568,  3168, 1568,  32),
    'hqc128':     (2249,  2305, 4433,  64),
    'hqc192':     (4522,  4586, 8978,  64),
    'hqc256':     (7245,  7317,14421,  64),
}

_SIGN = {
    # (pk, sk, max_sig)
    # ML-DSA
    'mldsa44':    (1312,  2560, 2420),
    'mldsa65':    (1952,  4032, 3309),
    'mldsa87':    (2592,  4896, 4627),
    # Falcon (standard — variable-length signature)
    'falcon512':  ( 897,  1281,  752),
    'falcon1024': (1793,  2305, 1462),
    # Falcon-padded (constant-length signature)
    'falconpadded512':  ( 897,  1281,  666),
    'falconpadded1024': (1793,  2305, 1280),
    # SPHINCS+-SHA2
    'sphincssha2128fsimple':  ( 32,   64, 17088),
    'sphincssha2128ssimple':  ( 32,   64,  7856),
    'sphincssha2192fsimple':  ( 48,   96, 35664),
    'sphincssha2192ssimple':  ( 48,   96, 16224),
    'sphincssha2256fsimple':  ( 64,  128, 49856),
    'sphincssha2256ssimple':  ( 64,  128, 29792),
    # SPHINCS+-SHAKE
    'sphincsshake128fsimple':  ( 32,   64, 17088),
    'sphincsshake128ssimple':  ( 32,   64,  7856),
    'sphincsshake192fsimple':  ( 48,   96, 35664),
    'sphincsshake192ssimple':  ( 48,   96, 16224),
    'sphincsshake256fsimple':  ( 64,  128, 49856),
    'sphincsshake256ssimple':  ( 64,  128, 29792),
}

_MSG = b"hello"


# ─────────────────────────────────────────────────────────────────────────────

def _kem_roundtrip(mod, name, pk_sz, sk_sz, ct_sz, ss_sz) -> bool:
    """
    keypair(pk, sk) → encaps(ct, ss1, pk) → decaps(ss2, ct, sk)
    Pass iff ss1 == ss2.
    """
    m = mod
    p_pk  = m.zbuf(pk_sz)
    p_sk  = m.zbuf(sk_sz)
    p_ct  = m.zbuf(ct_sz)
    p_ss1 = m.zbuf(ss_sz)
    p_ss2 = m.zbuf(ss_sz)

    if m.call(f'pqc_{name}_keypair', p_pk, p_sk) != 0:
        return False
    if m.call(f'pqc_{name}_encaps',  p_ct, p_ss1, p_pk) != 0:
        return False
    if m.call(f'pqc_{name}_decaps',  p_ss2, p_ct, p_sk) != 0:
        return False

    ss1 = m.read(p_ss1, ss_sz)
    ss2 = m.read(p_ss2, ss_sz)
    for p in (p_pk, p_sk, p_ct, p_ss1, p_ss2):
        m.free(p)
    return ss1 == ss2 and ss1 != b'\x00' * ss_sz


def _sign_roundtrip(mod, name, pk_sz, sk_sz, sig_sz) -> bool:
    """
    keypair(pk, sk) → sign(sig, siglen*, msg, mlen, sk)
                   → verify(sig, siglen, msg, mlen, pk) == 0
    """
    m = mod
    p_pk     = m.zbuf(pk_sz)
    p_sk     = m.zbuf(sk_sz)
    p_sig    = m.zbuf(sig_sz)
    p_siglen = m.zbuf(8)          # size_t: 4 bytes on WASM32, 8 is safe
    p_msg    = m.buf(_MSG)

    if m.call(f'pqc_{name}_keypair', p_pk, p_sk) != 0:
        return False
    if m.call(f'pqc_{name}_sign',
              p_sig, p_siglen, p_msg, len(_MSG), p_sk) != 0:
        return False

    # Read the actual siglen (i32 / size_t at p_siglen)
    import struct
    siglen = struct.unpack_from('<I', bytes(m.read(p_siglen, 4)))[0]
    if siglen == 0:
        return False

    verify_ok = m.call(f'pqc_{name}_verify',
                       p_sig, siglen, p_msg, len(_MSG), p_pk) == 0

    for p in (p_pk, p_sk, p_sig, p_siglen, p_msg):
        m.free(p)
    return verify_ok


# ─────────────────────────────────────────────────────────────────────────────

def _run_tests(mod) -> _Tester:
    t = _Tester()
    m = mod

    # ── KEM round-trips ───────────────────────────────────────────────────────
    for name, sizes in _KEM.items():
        label = name.upper().replace('HQC', 'HQC-').replace('MLKEM', 'ML-KEM-')
        t.run(f"{label} keypair/encaps/decaps",
              lambda n=name, s=sizes: _kem_roundtrip(m, n, *s))

    # ── Sign round-trips ──────────────────────────────────────────────────────
    for name, sizes in _SIGN.items():
        if 'mldsa' in name:
            label = name.replace('mldsa', 'ML-DSA-')
        elif 'falconpadded' in name:
            label = name.replace('falconpadded', 'Falcon-padded-')
        elif 'falcon' in name:
            label = name.replace('falcon', 'Falcon-')
        elif name.startswith('sphincssha2'):
            label = 'SPHINCS+-SHA2-' + name[len('sphincssha2'):]
        elif name.startswith('sphincsshake'):
            label = 'SPHINCS+-SHAKE-' + name[len('sphincsshake'):]
        else:
            label = name
        t.run(f"{label} keypair/sign/verify",
              lambda n=name, s=sizes: _sign_roundtrip(m, n, *s))

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True):
    """Run all pqc.wasm functional tests.  Returns 0 on pass, 1 on fail."""
    console.set_color(color)
    console.print_header("WASM pqc tests")

    mod, err = load_module('main', 'pqc')
    if mod is None:
        console.print_fail(f"Cannot load pqc.wasm: {err}")
        return 1

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(f"pqc.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
