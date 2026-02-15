import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import console

def main():
    """Run tests for core_cipher_main.dll (Base Tier)."""
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'base', 'core_cipher_main.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        # ---------------------------------------------------------
        # 1. AES-CBC Test
        # ---------------------------------------------------------
        console.print_step("Verifying AES-CBC symbol")
        lib.AES_CBC_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        
        ct_buf = ctypes.create_string_buffer(len(pt))
        lib.AES_CBC_encrypt(key, iv, pt, len(pt), ct_buf)
        
        if ct_buf.raw == expected_ct:
            console.print_pass("AES-CBC OK")
            console.log_data("AES-CBC.key", key.hex())
            console.log_data("AES-CBC.iv", iv.hex())
            console.log_data("AES-CBC.pt", pt.hex())
            console.log_data("AES-CBC.ct", ct_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("AES-CBC Failed")
            console.log_data("AES-CBC.ct (expected)", expected_ct.hex())
            console.log_data("AES-CBC.ct (actual)", ct_buf.raw.hex())
            failed += 1

        # ---------------------------------------------------------
        # 2. AES-GCM Test
        # ---------------------------------------------------------
        console.print_step("Verifying AES-GCM symbol")
        lib.AES_GCM_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        key_gcm = bytes(16)
        iv_gcm = bytes(12)
        tag_buf = ctypes.create_string_buffer(16)
        lib.AES_GCM_encrypt(key_gcm, iv_gcm, b"", 0, b"", 0, tag_buf)
        
        if tag_buf.raw.hex() == "58e2fccefa7e3061367f1d57a4e7455a":
            console.print_pass("AES-GCM OK")
            console.log_data("AES-GCM.key", key_gcm.hex())
            console.log_data("AES-GCM.iv", iv_gcm.hex())
            console.log_data("AES-GCM.tag", tag_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("AES-GCM Failed")
            failed += 1

        # ---------------------------------------------------------
        # 3. ChaCha20-Poly1305 Test
        # ---------------------------------------------------------
        console.print_step("Verifying ChaCha20-Poly1305 symbol")
        try:
            lib.ChaCha20_Poly1305_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            console.print_pass("ChaCha20-Poly1305 Symbol Found")
            passed += 1
        except Exception:
            console.print_fail("ChaCha20-Poly1305 Symbol Missing")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"Core Cipher Base: {passed} passed")
            return 0
        else:
            console.print_fail(f"Core Cipher Base: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
