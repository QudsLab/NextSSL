import ctypes
import os
import sys

# Add project root to sys.path to allow standalone execution
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '../../../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from script.core import Config, Logger, console

def main():
    """Run tests for pqc_kem_main.dll."""
    config = Config()
    
    dll_path = config.get_lib_path('base', 'pqc_kem_main')
    
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

        # 2. Deterministic Key Generation Test
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)
        
        pk1 = ctypes.create_string_buffer(pk_size)
        sk1 = ctypes.create_string_buffer(sk_size)
        pk2 = ctypes.create_string_buffer(pk_size)
        sk2 = ctypes.create_string_buffer(sk_size)
        pk3 = ctypes.create_string_buffer(pk_size)
        sk3 = ctypes.create_string_buffer(sk_size)

        # Gen Key 1 (Seed A)
        ret1 = keypair_derand_func(pk1, sk1, seed1)
        
        # Gen Key 2 (Seed A)
        ret2 = keypair_derand_func(pk2, sk2, seed1)
        
        # Gen Key 3 (Seed B)
        ret3 = keypair_derand_func(pk3, sk3, seed2)
        
        if ret1 == 0 and ret2 == 0 and ret3 == 0:
            if pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                test_pass(f"{algo_name} deterministic keygen (same seed)")
            else:
                test_fail(f"{algo_name} deterministic keygen (same seed)", "Keys differ with same seed")
                
            if pk1.raw != pk3.raw: # SK comparison might be tricky for some algos if they have random components, but usually SK is deterministic too
                test_pass(f"{algo_name} deterministic keygen (diff seed)")
            else:
                test_fail(f"{algo_name} deterministic keygen (diff seed)", "Keys match with different seed")
        else:
            test_fail(f"{algo_name} deterministic keygen", f"Returns: {ret1}, {ret2}, {ret3}")


    # ML-KEM-768
    test_kem("ML-KEM-768", 1184, 2400, 1088, 32,
             lib.pqc_mlkem768_keypair, lib.pqc_mlkem768_keypair_derand,
             lib.pqc_mlkem768_encaps, lib.pqc_mlkem768_encaps_derand,
             lib.pqc_mlkem768_decaps)

    # HQC-128
    # SK: 2305 (was 2289)
    test_kem("HQC-128", 2249, 2305, 4481, 64,
             lib.pqc_hqc128_keypair, lib.pqc_hqc128_keypair_derand,
             lib.pqc_hqc128_encaps, lib.pqc_hqc128_encaps_derand,
             lib.pqc_hqc128_decaps)
             
    # McEliece 348864
    # SK: 6492 (was 6452)
    test_kem("McEliece 348864", 261120, 6492, 128, 32,
             lib.pqc_mceliece348864_keypair, lib.pqc_mceliece348864_keypair_derand,
             lib.pqc_mceliece348864_encaps, lib.pqc_mceliece348864_encaps_derand,
             lib.pqc_mceliece348864_decaps)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
