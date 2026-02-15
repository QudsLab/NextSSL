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
    """Run all tests for sign_lattice.dll."""
    config = Config()
    
    dll_name = "sign_lattice" + Platform.get_shared_lib_ext()
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

    # ── Step 3: Define DRBG/UDBF function signatures ──
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

    # ── Test helper for SIGN ──
    def test_sign(algo_name, pk_size, sk_size, sig_size_max, 
                  keypair_func, keypair_derand_func, sign_func, sign_derand_func, verify_func):
        
        console.print_header(f"Testing {algo_name}")
        
        # Define signatures
        keypair_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        keypair_func.restype = ctypes.c_int
        
        keypair_derand_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        keypair_derand_func.restype = ctypes.c_int
        
        sign_func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        sign_func.restype = ctypes.c_int
        
        if "ML-DSA" in algo_name:
            sign_derand_func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        else:
            sign_derand_func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        sign_derand_func.restype = ctypes.c_int
        
        verify_func.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        verify_func.restype = ctypes.c_int

        # Buffers
        pk = ctypes.create_string_buffer(pk_size)
        sk = ctypes.create_string_buffer(sk_size)
        sig = ctypes.create_string_buffer(sig_size_max)
        siglen = ctypes.c_size_t(0)
        msg = b"test message"
        msglen = len(msg)

        # 1. OS Random Mode
        ret = keypair_func(pk, sk)
        console.print_info(f"{algo_name} keypair (OS random): ret={ret}")
        console.log_data(f"{algo_name}.keypair.pk", pk.raw.hex())
        console.log_data(f"{algo_name}.keypair.sk", sk.raw.hex())
        if ret == 0:
            test_pass(f"{algo_name} keypair")
        else:
            test_fail(f"{algo_name} keypair", f"returned {ret}")

        ret = sign_func(sig, ctypes.byref(siglen), msg, msglen, sk)
        console.print_info(f"{algo_name} sign: ret={ret}, siglen={siglen.value}")
        console.log_data(f"{algo_name}.sign.sig", sig.raw[:siglen.value].hex())
        if ret == 0:
            test_pass(f"{algo_name} sign")
        else:
            test_fail(f"{algo_name} sign", f"returned {ret}")

        ret = verify_func(sig, siglen, msg, msglen, pk)
        console.print_info(f"{algo_name} verify: ret={ret}")
        if ret == 0:
            test_pass(f"{algo_name} verify")
        else:
            test_fail(f"{algo_name} verify", f"returned {ret}")

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

        # 4. _derand Wrapper (Sign)
        sig_d = ctypes.create_string_buffer(sig_size_max)
        siglen_d = ctypes.c_size_t(0)
        
        if "ML-DSA" in algo_name:
            ret = sign_derand_func(sig_d, ctypes.byref(siglen_d), msg, msglen, None, 0, sk, seed)
        else:
            ret = sign_derand_func(sig_d, ctypes.byref(siglen_d), msg, msglen, sk, seed)
            
        if ret == 0:
            test_pass(f"{algo_name} sign_derand")
        else:
            test_fail(f"{algo_name} sign_derand", f"returned {ret}")

    # ── Execute Tests for ML-DSA ──
    # ML-DSA-44
    test_sign("ML-DSA-44", 1312, 2560, 2420,
              lib.pqc_mldsa44_keypair, lib.pqc_mldsa44_keypair_derand,
              lib.pqc_mldsa44_sign, lib.pqc_mldsa44_sign_derand,
              lib.pqc_mldsa44_verify)
    
    # ML-DSA-65
    test_sign("ML-DSA-65", 1952, 4032, 3309,
              lib.pqc_mldsa65_keypair, lib.pqc_mldsa65_keypair_derand,
              lib.pqc_mldsa65_sign, lib.pqc_mldsa65_sign_derand,
              lib.pqc_mldsa65_verify)

    # ML-DSA-87
    test_sign("ML-DSA-87", 2592, 4896, 4627,
              lib.pqc_mldsa87_keypair, lib.pqc_mldsa87_keypair_derand,
              lib.pqc_mldsa87_sign, lib.pqc_mldsa87_sign_derand,
              lib.pqc_mldsa87_verify)

    # ── Execute Tests for Falcon ──
    # Falcon-512
    test_sign("Falcon-512", 897, 1281, 666 + 200, # Add buffer for safety
              lib.pqc_falcon512_keypair, lib.pqc_falcon512_keypair_derand,
              lib.pqc_falcon512_sign, lib.pqc_falcon512_sign_derand,
              lib.pqc_falcon512_verify)

    # Falcon-1024
    test_sign("Falcon-1024", 1793, 2305, 1280 + 200,
              lib.pqc_falcon1024_keypair, lib.pqc_falcon1024_keypair_derand,
              lib.pqc_falcon1024_sign, lib.pqc_falcon1024_sign_derand,
              lib.pqc_falcon1024_verify)

    # Falcon-Padded-512
    test_sign("Falcon-Padded-512", 897, 1281, 666 + 200,
              lib.pqc_falconpadded512_keypair, lib.pqc_falconpadded512_keypair_derand,
              lib.pqc_falconpadded512_sign, lib.pqc_falconpadded512_sign_derand,
              lib.pqc_falconpadded512_verify)

    # Falcon-Padded-1024
    test_sign("Falcon-Padded-1024", 1793, 2305, 1280 + 200,
              lib.pqc_falconpadded1024_keypair, lib.pqc_falconpadded1024_keypair_derand,
              lib.pqc_falconpadded1024_sign, lib.pqc_falconpadded1024_sign_derand,
              lib.pqc_falconpadded1024_verify)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
