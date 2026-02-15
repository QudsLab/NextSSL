import ctypes
import os
import sys

# Add project root to sys.path to allow standalone execution
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '../../../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from script.core import Config, Logger, Platform, console

def main():
    """Run tests for pqc_sign_main.dll."""
    config = Config()
    
    dll_name = "pqc_sign_main" + Platform.get_shared_lib_ext()
    dll_path = os.path.join(config.bin_dir, 'base', dll_name)
    
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
        if ret == 0:
            test_pass(f"{algo_name} keypair")
        else:
            test_fail(f"{algo_name} keypair", f"returned {ret}")

        ret = sign_func(sig, ctypes.byref(siglen), msg, msglen, sk)
        console.print_info(f"{algo_name} sign: ret={ret}, siglen={siglen.value}")
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
                
            if pk1.raw != pk3.raw:
                test_pass(f"{algo_name} deterministic keygen (diff seed)")
            else:
                test_fail(f"{algo_name} deterministic keygen (diff seed)", "Keys match with different seed")
        else:
            test_fail(f"{algo_name} deterministic keygen", f"Returns: {ret1}, {ret2}, {ret3}")


    # ML-DSA-44
    test_sign("ML-DSA-44", 1312, 2560, 2420,
              lib.pqc_mldsa44_keypair, lib.pqc_mldsa44_keypair_derand,
              lib.pqc_mldsa44_sign, lib.pqc_mldsa44_sign_derand,
              lib.pqc_mldsa44_verify)
    
    # Falcon-512
    test_sign("Falcon-512", 897, 1281, 690,
              lib.pqc_falcon512_keypair, lib.pqc_falcon512_keypair_derand,
              lib.pqc_falcon512_sign, lib.pqc_falcon512_sign_derand,
              lib.pqc_falcon512_verify)
              
    # SPHINCS+ SHA2-128f-simple
    test_sign("SPHINCS+ SHA2-128f-simple", 32, 64, 17088,
              lib.pqc_sphincssha2128fsimple_keypair, lib.pqc_sphincssha2128fsimple_keypair_derand,
              lib.pqc_sphincssha2128fsimple_sign, lib.pqc_sphincssha2128fsimple_sign_derand,
              lib.pqc_sphincssha2128fsimple_verify)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
