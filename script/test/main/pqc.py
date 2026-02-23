import ctypes
import os
import sys
from script.core import Config, Logger, console

def main():
    """Run tests for pqc.dll (Main)."""
    config = Config()
    
    dll_path = config.get_lib_path('main', 'pqc')
    
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
        console.log_data(f"{algo_name}.sign.msg", msg.hex())
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

    # ML-KEM-768
    test_kem("ML-KEM-768", 1184, 2400, 1088, 32,
             lib.pqc_mlkem768_keypair, lib.pqc_mlkem768_keypair_derand,
             lib.pqc_mlkem768_encaps, lib.pqc_mlkem768_encaps_derand,
             lib.pqc_mlkem768_decaps)

    # ML-DSA-44
    test_sign("ML-DSA-44", 1312, 2560, 2420,
              lib.pqc_mldsa44_keypair, lib.pqc_mldsa44_keypair_derand,
              lib.pqc_mldsa44_sign, lib.pqc_mldsa44_sign_derand,
              lib.pqc_mldsa44_verify)

    # ── Summary ──
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
