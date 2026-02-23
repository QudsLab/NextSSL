import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, console

def main():
    """Run tests for aes_aead.dll."""
    try:
        config = Config()
        DLL_PATH = config.get_lib_path('partial', 'aes_aead', 'core')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        # Helper to log data
        def log_test(name, key, iv, pt, ct, tag=None):
            console.log_data(f"{name}.key", key.hex() if key else "None")
            if iv: console.log_data(f"{name}.iv", iv.hex())
            if pt: console.log_data(f"{name}.pt", pt.hex())
            if ct: console.log_data(f"{name}.ct", ct.hex())
            if tag: console.log_data(f"{name}.tag", tag.hex())

        # ---------------------------------------------------------
        # AES-GCM Test (NIST CAVP)
        # ---------------------------------------------------------
        console.print_step("Testing AES-GCM")
        
        # void AES_GCM_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* pntxt, size_t ptextLen, void* crtxt);
        lib.AES_GCM_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        # char AES_GCM_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* crtxt, size_t crtxtLen, void* pntxt);
        lib.AES_GCM_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.AES_GCM_decrypt.restype = ctypes.c_byte

        # Vectors
        # Key: 00...00 (16 bytes)
        # IV: 00...00 (12 bytes)
        # PT: (empty)
        # AAD: (empty)
        # Tag: 530f8afbc74536b9a963b4f1c4cb738b
        
        key = bytes(16)
        iv = bytes(12)
        pt = b""
        aad = b""
        expected_tag = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
        
        # Output buffer size = PT len + 16 (Tag)
        ct_buf = ctypes.create_string_buffer(len(pt) + 16)
        
        lib.AES_GCM_encrypt(key, iv, aad, len(aad), pt, len(pt), ct_buf)
        
        actual_tag = ct_buf.raw[-16:]
        if actual_tag == expected_tag:
            console.print_pass("AES-GCM Encrypt KAT")
            print(f"       Tag:        {actual_tag.hex()}")
            log_test("AES-GCM", key, iv, pt, ct_buf.raw, actual_tag)
            passed += 1
        else:
            console.print_fail("AES-GCM Encrypt KAT mismatch")
            console.print_fail(f"Expected Tag: {expected_tag.hex()}")
            console.print_fail(f"Actual Tag:   {actual_tag.hex()}")
            failed += 1

        # Decrypt (valid)
        pt_out = ctypes.create_string_buffer(len(pt))
        ret = lib.AES_GCM_decrypt(key, iv, aad, len(aad), ct_buf, len(pt), pt_out)
        
        if ret == 0:
            console.print_pass("AES-GCM Decrypt (Valid)")
            passed += 1
        else:
            console.print_fail("AES-GCM Decrypt failed on valid input")
            failed += 1

        # Decrypt (tampered)
        tampered_ct = bytearray(ct_buf.raw)
        tampered_ct[0] ^= 0x01
        tampered_ct_buf = ctypes.create_string_buffer(bytes(tampered_ct))
        
        ret = lib.AES_GCM_decrypt(key, iv, aad, len(aad), tampered_ct_buf, len(tampered_ct_buf), pt_out)
        
        if ret != 0:
            console.print_pass("AES-GCM Decrypt (Tampered) correctly rejected")
            passed += 1
        else:
            console.print_fail("AES-GCM Decrypt ACCEPTED tampered input!")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"AES AEAD: {passed} passed")
            return 0
        else:
            console.print_fail(f"AES AEAD: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
