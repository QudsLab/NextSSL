"""script/test/main/pqc.py â€” functional tests for pqc.dll (Main Tier).

Covers all 35 PQC algorithms (ML-KEM, HQC, McEliece, ML-DSA,
Falcon, Falcon-Padded, SPHINCS+-SHA2, SPHINCS+-SHAKE) using
run_kem() / run_sign() helpers from test/core/.
"""
import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from script.core             import Config, console
from script.test.core.result import Results
from script.test.core.kem    import run_kem
from script.test.core.sign   import run_sign


def main() -> int:
    config   = Config()
    dll_path = config.get_lib_path('main', 'pqc')
    console.print_info(f"Loading: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1
    console.print_pass("DLL loaded")

    r = Results('test/main/pqc')

    # â”€â”€ ML-KEM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_kem(lib, "ML-KEM-512",
            800, 1632, 768, 32,
            'pqc_mlkem512_keypair', 'pqc_mlkem512_keypair_derand',
            'pqc_mlkem512_encaps',  'pqc_mlkem512_encaps_derand',
            'pqc_mlkem512_decaps',  r)

    run_kem(lib, "ML-KEM-768",
            1184, 2400, 1088, 32,
            'pqc_mlkem768_keypair', 'pqc_mlkem768_keypair_derand',
            'pqc_mlkem768_encaps',  'pqc_mlkem768_encaps_derand',
            'pqc_mlkem768_decaps',  r)

    run_kem(lib, "ML-KEM-1024",
            1568, 3168, 1568, 32,
            'pqc_mlkem1024_keypair', 'pqc_mlkem1024_keypair_derand',
            'pqc_mlkem1024_encaps',  'pqc_mlkem1024_encaps_derand',
            'pqc_mlkem1024_decaps',  r)

    # â”€â”€ HQC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_kem(lib, "HQC-128",
            2249, 2289, 4481, 64,
            'pqc_hqc128_keypair', 'pqc_hqc128_keypair_derand',
            'pqc_hqc128_encaps',  'pqc_hqc128_encaps_derand',
            'pqc_hqc128_decaps',  r)

    run_kem(lib, "HQC-192",
            4522, 4562, 9026, 64,
            'pqc_hqc192_keypair', 'pqc_hqc192_keypair_derand',
            'pqc_hqc192_encaps',  'pqc_hqc192_encaps_derand',
            'pqc_hqc192_decaps',  r)

    run_kem(lib, "HQC-256",
            7245, 7285, 14469, 64,
            'pqc_hqc256_keypair', 'pqc_hqc256_keypair_derand',
            'pqc_hqc256_encaps',  'pqc_hqc256_encaps_derand',
            'pqc_hqc256_decaps',  r)

    # â”€â”€ McEliece â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _mceliece_variants = [
        ("McEliece-348864",  261120,  6452,  96, 32, 'mceliece348864'),
        ("McEliece-348864f", 261120,  6452,  96, 32, 'mceliece348864f'),
        ("McEliece-460896",  524160, 13568, 156, 32, 'mceliece460896'),
        ("McEliece-460896f", 524160, 13568, 156, 32, 'mceliece460896f'),
        ("McEliece-6688128", 1044992, 13892, 208, 32, 'mceliece6688128'),
        ("McEliece-6688128f",1044992, 13892, 208, 32, 'mceliece6688128f'),
        ("McEliece-6960119", 1047319, 13948, 194, 32, 'mceliece6960119'),
        ("McEliece-6960119f",1047319, 13948, 194, 32, 'mceliece6960119f'),
        ("McEliece-8192128", 1357824, 14080, 208, 32, 'mceliece8192128'),
        ("McEliece-8192128f",1357824, 14080, 208, 32, 'mceliece8192128f'),
    ]
    for name, pk, sk, ct, ss, tag in _mceliece_variants:
        run_kem(lib, name, pk, sk, ct, ss,
                f'pqc_{tag}_keypair',          f'pqc_{tag}_keypair_derand',
                f'pqc_{tag}_encaps',           f'pqc_{tag}_encaps_derand',
                f'pqc_{tag}_decaps',           r)

    # â”€â”€ ML-DSA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_sign(lib, "ML-DSA-44",
             1312, 2560, 2420,
             'pqc_mldsa44_keypair', 'pqc_mldsa44_keypair_derand',
             'pqc_mldsa44_sign',    'pqc_mldsa44_sign_derand',
             'pqc_mldsa44_verify',  r, mldsa=True)

    run_sign(lib, "ML-DSA-65",
             1952, 4032, 3309,
             'pqc_mldsa65_keypair', 'pqc_mldsa65_keypair_derand',
             'pqc_mldsa65_sign',    'pqc_mldsa65_sign_derand',
             'pqc_mldsa65_verify',  r, mldsa=True)

    run_sign(lib, "ML-DSA-87",
             2592, 4896, 4627,
             'pqc_mldsa87_keypair', 'pqc_mldsa87_keypair_derand',
             'pqc_mldsa87_sign',    'pqc_mldsa87_sign_derand',
             'pqc_mldsa87_verify',  r, mldsa=True)

    # â”€â”€ Falcon â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_sign(lib, "Falcon-512",
             897, 1281, 752,
             'pqc_falcon512_keypair', 'pqc_falcon512_keypair_derand',
             'pqc_falcon512_sign',    'pqc_falcon512_sign_derand',
             'pqc_falcon512_verify',  r)

    run_sign(lib, "Falcon-1024",
             1793, 2305, 1330,
             'pqc_falcon1024_keypair', 'pqc_falcon1024_keypair_derand',
             'pqc_falcon1024_sign',    'pqc_falcon1024_sign_derand',
             'pqc_falcon1024_verify',  r)

    run_sign(lib, "Falcon-Padded-512",
             897, 1281, 666,
             'pqc_falconpadded512_keypair', 'pqc_falconpadded512_keypair_derand',
             'pqc_falconpadded512_sign',    'pqc_falconpadded512_sign_derand',
             'pqc_falconpadded512_verify',  r)

    run_sign(lib, "Falcon-Padded-1024",
             1793, 2305, 1280,
             'pqc_falconpadded1024_keypair', 'pqc_falconpadded1024_keypair_derand',
             'pqc_falconpadded1024_sign',    'pqc_falconpadded1024_sign_derand',
             'pqc_falconpadded1024_verify',  r)

    # â”€â”€ SPHINCS+-SHA2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _sphincs_sha2 = [
        ("SPHINCS+-SHA2-128f", 32,  64,  17088, 'sphincssha2128fsimple'),
        ("SPHINCS+-SHA2-128s", 32,  64,   7856, 'sphincssha2128ssimple'),
        ("SPHINCS+-SHA2-192f", 48,  96,  35664, 'sphincssha2192fsimple'),
        ("SPHINCS+-SHA2-192s", 48,  96,  16224, 'sphincssha2192ssimple'),
        ("SPHINCS+-SHA2-256f", 64, 128,  49856, 'sphincssha2256fsimple'),
        ("SPHINCS+-SHA2-256s", 64, 128,  29792, 'sphincssha2256ssimple'),
    ]
    for name, pk, sk, sig, tag in _sphincs_sha2:
        run_sign(lib, name, pk, sk, sig,
                 f'pqc_{tag}_keypair',          f'pqc_{tag}_keypair_derand',
                 f'pqc_{tag}_sign',             f'pqc_{tag}_sign_derand',
                 f'pqc_{tag}_verify',           r)

    # â”€â”€ SPHINCS+-SHAKE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _sphincs_shake = [
        ("SPHINCS+-SHAKE-128f", 32,  64,  17088, 'sphincsshake128fsimple'),
        ("SPHINCS+-SHAKE-128s", 32,  64,   7856, 'sphincsshake128ssimple'),
        ("SPHINCS+-SHAKE-192f", 48,  96,  35664, 'sphincsshake192fsimple'),
        ("SPHINCS+-SHAKE-192s", 48,  96,  16224, 'sphincsshake192ssimple'),
        ("SPHINCS+-SHAKE-256f", 64, 128,  49856, 'sphincsshake256fsimple'),
        ("SPHINCS+-SHAKE-256s", 64, 128,  29792, 'sphincsshake256ssimple'),
    ]
    for name, pk, sk, sig, tag in _sphincs_shake:
        run_sign(lib, name, pk, sk, sig,
                 f'pqc_{tag}_keypair',          f'pqc_{tag}_keypair_derand',
                 f'pqc_{tag}_sign',             f'pqc_{tag}_sign_derand',
                 f'pqc_{tag}_verify',           r)

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
    
