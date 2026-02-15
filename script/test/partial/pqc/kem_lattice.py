import ctypes
import os
import sys
import random

# Add project root to sys.path to allow standalone execution
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '../../../../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from script.core import Config, Logger, Platform, console

def main():
    """Run all tests for kem_lattice.dll."""
    config = Config()
    
    # ── Step 1: Resolve DLL path ──
    # Note: runner.py usually runs from project root, but standalone execution should work too.
    # The Config class handles paths relative to project root.
    # We construct path manually to be explicit as per TASK_PQC.md, or use config.
    # Using config is better but let's stick to the pattern in TASK_PQC.md for clarity if desired.
    # Actually, TASK_PQC.md uses os.path.join from __file__.
    # But since we have Config, let's use it to get bin_dir.
    
    dll_name = "kem_lattice" + Platform.get_shared_lib_ext()
    dll_path = os.path.join(config.bin_dir, 'partial', 'pqc', dll_name)
    
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

    # ── Step 3: Define DRBG/UDBF function signatures (available in EVERY PQC DLL) ──
    lib.pqc_randombytes_seed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.pqc_randombytes_seed.restype = None

    lib.pqc_randombytes_reseed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.pqc_randombytes_reseed.restype = None

    lib.pqc_set_udbf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
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
        seed = bytes(range(32))
        console.log_data(f"{algo_name}.drbg.seed", seed.hex())
        lib.pqc_randombytes_seed(seed, 32)
        
        pk1 = ctypes.create_string_buffer(pk_size)
        sk1 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk1, sk1)
        
        lib.pqc_randombytes_seed(seed, 32)
        pk2 = ctypes.create_string_buffer(pk_size)
        sk2 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk2, sk2)
        
        if pk1.raw == pk2.raw and sk1.raw == sk2.raw:
            test_pass(f"{algo_name} DRBG determinism")
        else:
            test_fail(f"{algo_name} DRBG determinism", "keypairs differ with same seed")

        # 3. UDBF Determinism
        # Use a large buffer (5MB)
        rng = random.Random(42)
        udbf_seed = 42
        console.log_data(f"{algo_name}.udbf.seed_value", str(udbf_seed))
        raw_bytes = rng.randbytes(5 * 1024 * 1024)
        console.log_data(f"{algo_name}.udbf.first_32_bytes", raw_bytes[:32].hex())
        udbf_buf = ctypes.create_string_buffer(raw_bytes)
        
        lib.pqc_set_udbf(udbf_buf, len(raw_bytes))
        
        pk_u1 = ctypes.create_string_buffer(pk_size)
        sk_u1 = ctypes.create_string_buffer(sk_size)
        keypair_func(pk_u1, sk_u1)
        
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
        ret = keypair_derand_func(pk_d, sk_d, seed)
        if ret == 0:
            test_pass(f"{algo_name} keypair_derand")
        else:
            test_fail(f"{algo_name} keypair_derand", f"returned {ret}")

    # ── Execute Tests for each algo ──
    
    # ML-KEM-512
    test_kem("ML-KEM-512", 800, 1632, 768, 32,
             lib.pqc_mlkem512_keypair, lib.pqc_mlkem512_keypair_derand,
             lib.pqc_mlkem512_encaps, lib.pqc_mlkem512_encaps_derand,
             lib.pqc_mlkem512_decaps)

    # ML-KEM-768
    test_kem("ML-KEM-768", 1184, 2400, 1088, 32,
             lib.pqc_mlkem768_keypair, lib.pqc_mlkem768_keypair_derand,
             lib.pqc_mlkem768_encaps, lib.pqc_mlkem768_encaps_derand,
             lib.pqc_mlkem768_decaps)

    # ML-KEM-1024
    test_kem("ML-KEM-1024", 1568, 3168, 1568, 32,
             lib.pqc_mlkem1024_keypair, lib.pqc_mlkem1024_keypair_derand,
             lib.pqc_mlkem1024_encaps, lib.pqc_mlkem1024_encaps_derand,
             lib.pqc_mlkem1024_decaps)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
