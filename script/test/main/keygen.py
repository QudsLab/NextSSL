"""script/test/main/keygen.py — functional tests for one-shot keygen (Main Tier).

Tests all 40 algorithms × 4 modes (random, drbg, password, hd) using
run_keygen_oneshotmodes() from test/core/keygen_runner.
Keygen functions live in core.dll alongside the cipher/ECC primitives.
"""
import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from script.core                    import Config, console
from script.test.core.result        import Results
from script.test.core.keygen_runner import run_keygen_oneshotmodes

_ALL_MODES = ['random', 'drbg', 'password', 'hd']

# (display_name, algo_tag, pk_size, sk_size)
_ALGOS = [
    # ── ECC / symmetric ────────────────────────────────────────────────────
    ("Ed25519",            "ed25519",           32,      64),
    ("X25519",             "x25519",            32,      32),
    ("Ed448",              "ed448",             57,      57),
    ("X448",               "x448",              56,      56),
    ("Elligator2",         "elligator2",        32,      32),
    # ── ML-KEM ─────────────────────────────────────────────────────────────
    ("ML-KEM-512",         "ml_kem_512",       800,    1632),
    ("ML-KEM-768",         "ml_kem_768",      1184,    2400),
    ("ML-KEM-1024",        "ml_kem_1024",     1568,    3168),
    # ── ML-DSA ─────────────────────────────────────────────────────────────
    ("ML-DSA-44",          "ml_dsa_44",       1312,    2560),
    ("ML-DSA-65",          "ml_dsa_65",       1952,    4032),
    ("ML-DSA-87",          "ml_dsa_87",       2592,    4896),
    # ── Falcon ─────────────────────────────────────────────────────────────
    ("Falcon-512",         "falcon_512",       897,    1281),
    ("Falcon-1024",        "falcon_1024",     1793,    2305),
    ("Falcon-Padded-512",  "falcon_padded_512",  897, 1281),
    ("Falcon-Padded-1024", "falcon_padded_1024", 1793, 2305),
    # ── SPHINCS+-SHA2 ──────────────────────────────────────────────────────
    ("SPHINCS+-SHA2-128f", "sphincs_sha2_128f", 32,    64),
    ("SPHINCS+-SHA2-128s", "sphincs_sha2_128s", 32,    64),
    ("SPHINCS+-SHA2-192f", "sphincs_sha2_192f", 48,    96),
    ("SPHINCS+-SHA2-192s", "sphincs_sha2_192s", 48,    96),
    ("SPHINCS+-SHA2-256f", "sphincs_sha2_256f", 64,   128),
    ("SPHINCS+-SHA2-256s", "sphincs_sha2_256s", 64,   128),
    # ── SPHINCS+-SHAKE ─────────────────────────────────────────────────────
    ("SPHINCS+-SHAKE-128f", "sphincs_shake_128f", 32,  64),
    ("SPHINCS+-SHAKE-128s", "sphincs_shake_128s", 32,  64),
    ("SPHINCS+-SHAKE-192f", "sphincs_shake_192f", 48,  96),
    ("SPHINCS+-SHAKE-192s", "sphincs_shake_192s", 48,  96),
    ("SPHINCS+-SHAKE-256f", "sphincs_shake_256f", 64, 128),
    ("SPHINCS+-SHAKE-256s", "sphincs_shake_256s", 64, 128),
    # ── HQC ────────────────────────────────────────────────────────────────
    ("HQC-128",            "hqc_128",         2249,    2289),
    ("HQC-192",            "hqc_192",         4522,    4562),
    ("HQC-256",            "hqc_256",         7245,    7285),
    # ── McEliece ───────────────────────────────────────────────────────────
    ("McEliece-348864",    "mceliece_348864",   261120,  6452),
    ("McEliece-348864f",   "mceliece_348864f",  261120,  6452),
    ("McEliece-460896",    "mceliece_460896",   524160, 13568),
    ("McEliece-460896f",   "mceliece_460896f",  524160, 13568),
    ("McEliece-6688128",   "mceliece_6688128", 1044992, 13892),
    ("McEliece-6688128f",  "mceliece_6688128f",1044992, 13892),
    ("McEliece-6960119",   "mceliece_6960119", 1047319, 13948),
    ("McEliece-6960119f",  "mceliece_6960119f",1047319, 13948),
    ("McEliece-8192128",   "mceliece_8192128", 1357824, 14080),
    ("McEliece-8192128f",  "mceliece_8192128f",1357824, 14080),
]


def main() -> int:
    config   = Config()
    dll_path = config.get_lib_path('main', 'core')
    console.print_info(f"Loading: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    try:
        # core.dll depends on pqc.dll at runtime (PQC keygen functions).
        # Pre-load pqc.dll and register its directory so Windows can find it.
        bin_dir = os.path.dirname(os.path.abspath(dll_path))
        if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(bin_dir)
        pqc_path = config.get_lib_path('main', 'pqc')
        if os.path.exists(pqc_path):
            ctypes.CDLL(pqc_path)
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1
    console.print_pass("DLL loaded")

    r = Results('test/main/keygen')

    for display, algo_tag, pk_size, sk_size in _ALGOS:
        console.print_info(f"Keygen: {display}")
        run_keygen_oneshotmodes(lib, algo_tag, pk_size, sk_size, _ALL_MODES, r)

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
