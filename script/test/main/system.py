import ctypes
import os
import sys
from script.core import console

def main():
    try:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        dll_path = os.path.join(root, 'bin', 'main.dll')
        
        console.print_step(f"Loading {dll_path}")
        if not os.path.exists(dll_path):
            console.print_fail(f"DLL not found: {dll_path}")
            return 1
            
        lib = ctypes.CDLL(dll_path)
        console.print_pass("DLL Loaded")
        
        failed = 0
        
        try:
            lib.leyline_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            out = ctypes.create_string_buffer(32)
            lib.leyline_sha256(b"abc", 3, out)
            if out.raw.hex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
                console.print_fail("SHA256 mismatch")
                failed += 1
            else:
                console.print_pass("SHA256 OK")
        except Exception as e:
            console.print_fail(f"SHA256 failed: {e}")
            failed += 1
        
        try:
            lib.leyline_dhcm_expected_trials.argtypes = [ctypes.c_int, ctypes.c_uint32]
            lib.leyline_dhcm_expected_trials.restype = ctypes.c_double
            val = lib.leyline_dhcm_expected_trials(1, 8)
            if val <= 0:
                console.print_fail("DHCM expected trials invalid")
                failed += 1
            else:
                console.print_pass("DHCM OK")
        except Exception as e:
            console.print_fail(f"DHCM failed: {e}")
            failed += 1
        
        try:
            _ = lib.leyline_pow_server_generate_challenge
            _ = lib.leyline_pow_client_solve
            console.print_pass("PoW symbols OK")
        except Exception as e:
            console.print_fail(f"PoW symbols missing: {e}")
            failed += 1
        
        try:
            _ = lib.pqc_mlkem512_keypair
            console.print_pass("PQC symbols OK")
        except Exception as e:
            console.print_fail(f"PQC symbols missing: {e}")
            failed += 1
        
        try:
            lib.AES_CBC_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
            iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
            pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
            expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
            ct_buf = ctypes.create_string_buffer(len(pt))
            lib.AES_CBC_encrypt(key, iv, pt, len(pt), ct_buf)
            if ct_buf.raw != expected_ct:
                console.print_fail("AES-CBC mismatch")
                failed += 1
            else:
                console.print_pass("AES-CBC OK")
        except Exception as e:
            console.print_fail(f"AES-CBC failed: {e}")
            failed += 1
        
        if failed == 0:
            console.print_pass("Main unified DLL OK")
            return 0
        console.print_fail(f"Main unified DLL failed: {failed}")
        return 1
    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
