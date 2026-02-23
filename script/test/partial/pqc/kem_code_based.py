import ctypes
import os
import sys
import random

# Add project root to sys.path to allow standalone execution
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '../../../../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from script.core import Config, Logger, console

def main():
    """Run all tests for kem_code_based.dll."""
    config = Config()
    
    dll_path = config.get_lib_path('partial', 'kem_code_based', 'pqc')
    
    console.print_info(f"Loading DLL: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
        
    try:
        lib = ctypes.CDLL(dll_path)
        console.print_pass("DLL loaded successfully")
    except Exception as e:
        console.print_fail(f"Failed to load DLL: {e}")
        return 1

    # ── Step 3: Define DRBG/UDBF function signatures ──
    lib.pqc_randombytes_seed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.pqc_randombytes_seed.restype = None

    lib.pqc_randombytes_reseed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.pqc_randombytes_reseed.restype = None

    lib.pqc_set_udbf.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.pqc_set_udbf.restype = None

    # ── Step 5: Run tests ──
    passed = 0
    failed = 0

    def test_pass(name):
        nonlocal passed
        console.print_pass(name)
        passed += 1

    def test_fail(name, reason=""):
        nonlocal failed
        console.print_fail(name)
        if reason:
            console.print_fail(f"Reason: {reason}")
        failed += 1

    # ── Test helper for KEM ──
    def test_kem(algo_name, pk_size, sk_size, ct_size, ss_size, 
                 keypair_func, keypair_derand_func, encaps_func, encaps_derand_func, decaps_func):
        
        console.print_header(f"Testing {algo_name}")
        
        # Define signatures
        keypair_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        keypair_func.restype = ctypes.c_int
        
        keypair_derand_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        keypair_derand_func.restype = ctypes.c_int
        
        encaps_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        encaps_func.restype = ctypes.c_int
        
        encaps_derand_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        encaps_derand_func.restype = ctypes.c_int
        
        decaps_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        decaps_func.restype = ctypes.c_int

        # Buffers
        pk = ctypes.create_string_buffer(pk_size)
        sk = ctypes.create_string_buffer(sk_size)
        ct = ctypes.create_string_buffer(ct_size)
        ss_enc = ctypes.create_string_buffer(ss_size)
        ss_dec = ctypes.create_string_buffer(ss_size)

        # 1. OS Random Mode
        ret = keypair_func(pk, sk)
        console.print_info(f"{algo_name} keypair (OS random): ret={ret}")
        console.log_data(f"{algo_name}.keypair.pk", pk.raw.hex())
        console.log_data(f"{algo_name}.keypair.sk", sk.raw.hex())
        if ret == 0:
            test_pass(f"{algo_name} keypair")
        else:
            test_fail(f"{algo_name} keypair", f"returned {ret}")

        ret = encaps_func(ct, ss_enc, pk)
        console.print_info(f"{algo_name} encaps: ret={ret}")
        console.log_data(f"{algo_name}.encaps.ct", ct.raw.hex())
        console.log_data(f"{algo_name}.encaps.ss", ss_enc.raw.hex())
        if ret == 0:
            test_pass(f"{algo_name} encaps")
        else:
            test_fail(f"{algo_name} encaps", f"returned {ret}")

        ret = decaps_func(ss_dec, ct, sk)
        console.print_info(f"{algo_name} decaps: ret={ret}")
        console.log_data(f"{algo_name}.decaps.ss", ss_dec.raw.hex())
        if ret == 0 and ss_enc.raw == ss_dec.raw:
            test_pass(f"{algo_name} decaps + shared secret match")
        else:
            test_fail(f"{algo_name} decaps", "shared secret mismatch" if ret == 0 else f"returned {ret}")

        # 2. DRBG Determinism
        seed_bytes = bytes(range(32))
        seed_buf = ctypes.create_string_buffer(seed_bytes)
        console.log_data(f"{algo_name}.drbg.seed", seed_bytes.hex())
        
        lib.pqc_randombytes_seed(seed_buf, 32)
        
        pk1 = ctypes.create_string_buffer(pk_size)
        sk1 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk1, sk1)
        
        lib.pqc_randombytes_seed(seed_buf, 32)
        pk2 = ctypes.create_string_buffer(pk_size)
        sk2 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk2, sk2)
        
        if pk1.raw == pk2.raw and sk1.raw == sk2.raw:
            test_pass(f"{algo_name} DRBG determinism")
        else:
            test_fail(f"{algo_name} DRBG determinism", "keypairs differ with same seed")

        # 3. UDBF Determinism
        console.print_info(f"       Generating UDBF data (15MB)...")
        # Use a large buffer (15MB) to avoid exhaustion during McEliece keygen
        # Use random.Random(42) for deterministic "random-looking" data
        rng = random.Random(42)
        udbf_seed = 42
        console.log_data(f"{algo_name}.udbf.seed_value", str(udbf_seed))
        raw_bytes = rng.randbytes(15 * 1024 * 1024)
        console.log_data(f"{algo_name}.udbf.first_32_bytes", raw_bytes[:32].hex())
        # Create a persistent mutable buffer to ensure pointer validity
        udbf_buf = ctypes.create_string_buffer(raw_bytes)
        
        console.print_info(f"       Run 1 with UDBF...")
        lib.pqc_set_udbf(udbf_buf, len(raw_bytes))
        
        pk_u1 = ctypes.create_string_buffer(pk_size)
        sk_u1 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk_u1, sk_u1)
        
        console.print_info(f"       Run 2 with UDBF...")
        lib.pqc_set_udbf(udbf_buf, len(raw_bytes))
        pk_u2 = ctypes.create_string_buffer(pk_size)
        sk_u2 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk_u2, sk_u2)
        
        if pk_u1.raw == pk_u2.raw:
            test_pass(f"{algo_name} UDBF determinism")
        else:
            test_fail(f"{algo_name} UDBF determinism", "keypairs differ with same buffer")

        # 4. _derand Wrapper
        pk_d = ctypes.create_string_buffer(pk_size)
        sk_d = ctypes.create_string_buffer(sk_size)
        ret = keypair_derand_func(pk_d, sk_d, seed_buf)
        if ret == 0:
            test_pass(f"{algo_name} keypair_derand")
        else:
            test_fail(f"{algo_name} keypair_derand", f"returned {ret}")

    # ── Execute Tests for HQC ──
    # HQC-128
    # SK: 2305 (was 2289)
    test_kem("HQC-128", 2249, 2305, 4481, 64,
             lib.pqc_hqc128_keypair, lib.pqc_hqc128_keypair_derand,
             lib.pqc_hqc128_encaps, lib.pqc_hqc128_encaps_derand,
             lib.pqc_hqc128_decaps)
    # HQC-192
    # SK: 4586 (was 4562)
    test_kem("HQC-192", 4522, 4586, 9026, 64,
             lib.pqc_hqc192_keypair, lib.pqc_hqc192_keypair_derand,
             lib.pqc_hqc192_encaps, lib.pqc_hqc192_encaps_derand,
             lib.pqc_hqc192_decaps)
    # HQC-256
    # SK: 7317 (was 7285)
    test_kem("HQC-256", 7245, 7317, 14469, 64,
             lib.pqc_hqc256_keypair, lib.pqc_hqc256_keypair_derand,
             lib.pqc_hqc256_encaps, lib.pqc_hqc256_encaps_derand,
             lib.pqc_hqc256_decaps)

    # ── Execute Tests for McEliece ──
    # McEliece 348864
    # SK: 6492 (was 6452)
    test_kem("McEliece 348864", 261120, 6492, 128, 32,
             lib.pqc_mceliece348864_keypair, lib.pqc_mceliece348864_keypair_derand,
             lib.pqc_mceliece348864_encaps, lib.pqc_mceliece348864_encaps_derand,
             lib.pqc_mceliece348864_decaps)
             
    # McEliece 348864f
    test_kem("McEliece 348864f", 261120, 6492, 128, 32,
             lib.pqc_mceliece348864f_keypair, lib.pqc_mceliece348864f_keypair_derand,
             lib.pqc_mceliece348864f_encaps, lib.pqc_mceliece348864f_encaps_derand,
             lib.pqc_mceliece348864f_decaps)

    # McEliece 460896
    test_kem("McEliece 460896", 524160, 13608, 156, 32,
             lib.pqc_mceliece460896_keypair, lib.pqc_mceliece460896_keypair_derand,
             lib.pqc_mceliece460896_encaps, lib.pqc_mceliece460896_encaps_derand,
             lib.pqc_mceliece460896_decaps)

    # McEliece 460896f
    test_kem("McEliece 460896f", 524160, 13608, 156, 32,
             lib.pqc_mceliece460896f_keypair, lib.pqc_mceliece460896f_keypair_derand,
             lib.pqc_mceliece460896f_encaps, lib.pqc_mceliece460896f_encaps_derand,
             lib.pqc_mceliece460896f_decaps)

    # McEliece 6688128
    test_kem("McEliece 6688128", 1044992, 13932, 208, 32,
             lib.pqc_mceliece6688128_keypair, lib.pqc_mceliece6688128_keypair_derand,
             lib.pqc_mceliece6688128_encaps, lib.pqc_mceliece6688128_encaps_derand,
             lib.pqc_mceliece6688128_decaps)

    # McEliece 6688128f
    test_kem("McEliece 6688128f", 1044992, 13932, 208, 32,
             lib.pqc_mceliece6688128f_keypair, lib.pqc_mceliece6688128f_keypair_derand,
             lib.pqc_mceliece6688128f_encaps, lib.pqc_mceliece6688128f_encaps_derand,
             lib.pqc_mceliece6688128f_decaps)

    # McEliece 6960119
    test_kem("McEliece 6960119", 1047319, 13948, 194, 32,
             lib.pqc_mceliece6960119_keypair, lib.pqc_mceliece6960119_keypair_derand,
             lib.pqc_mceliece6960119_encaps, lib.pqc_mceliece6960119_encaps_derand,
             lib.pqc_mceliece6960119_decaps)

    # McEliece 6960119f
    test_kem("McEliece 6960119f", 1047319, 13948, 194, 32,
             lib.pqc_mceliece6960119f_keypair, lib.pqc_mceliece6960119f_keypair_derand,
             lib.pqc_mceliece6960119f_encaps, lib.pqc_mceliece6960119f_encaps_derand,
             lib.pqc_mceliece6960119f_decaps)

    # McEliece 8192128
    test_kem("McEliece 8192128", 1357824, 14120, 208, 32,
             lib.pqc_mceliece8192128_keypair, lib.pqc_mceliece8192128_keypair_derand,
             lib.pqc_mceliece8192128_encaps, lib.pqc_mceliece8192128_encaps_derand,
             lib.pqc_mceliece8192128_decaps)

    # McEliece 8192128f
    test_kem("McEliece 8192128f", 1357824, 14120, 208, 32,
             lib.pqc_mceliece8192128f_keypair, lib.pqc_mceliece8192128f_keypair_derand,
             lib.pqc_mceliece8192128f_encaps, lib.pqc_mceliece8192128f_encaps_derand,
             lib.pqc_mceliece8192128f_decaps)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
