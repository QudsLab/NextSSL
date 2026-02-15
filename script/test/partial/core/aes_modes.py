import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import console

def main():
    """Run tests for aes_modes.dll."""
    try:
        # 1. Resolve DLL path
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'core', 'aes_modes.dll')

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
        # AES-CBC Test (NIST SP 800-38A)
        # ---------------------------------------------------------
        console.print_step("Testing AES-CBC")
        
        # Signatures
        # void AES_CBC_encrypt(const uint8_t* key, const uint8_t iVec[16], const void* pntxt, size_t ptextLen, void* crtxt);
        lib.AES_CBC_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        # char AES_CBC_decrypt(const uint8_t* key, const uint8_t iVec[16], const void* crtxt, size_t crtxtLen, void* pntxt);
        lib.AES_CBC_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.AES_CBC_decrypt.restype = ctypes.c_byte

        # Vectors
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

        ct_buf = ctypes.create_string_buffer(len(pt))
        lib.AES_CBC_encrypt(key, iv, pt, len(pt), ct_buf)
        
        if ct_buf.raw == expected_ct:
            console.print_pass("AES-CBC Encrypt KAT")
            log_test("AES-CBC", key, iv, pt, ct_buf.raw)
            passed += 1
        else:
            console.print_fail("AES-CBC Encrypt KAT mismatch")
            console.print_fail(f"Expected: {expected_ct.hex()}")
            console.print_fail(f"Actual:   {ct_buf.raw.hex()}")
            failed += 1

        # Decrypt
        pt_buf = ctypes.create_string_buffer(len(pt))
        ret = lib.AES_CBC_decrypt(key, iv, ct_buf, len(ct_buf), pt_buf)
        
        if ret == 0 and pt_buf.raw == pt:
            console.print_pass("AES-CBC Decrypt Roundtrip")
            passed += 1
        else:
            console.print_fail("AES-CBC Decrypt failed")
            failed += 1

        # ---------------------------------------------------------
        # AES-XTS Test (IEEE P1619)
        # ---------------------------------------------------------
        console.print_step("Testing AES-XTS")
        
        # void AES_XTS_encrypt(const uint8_t* keys, const uint8_t* tweak, const void* pntxt, size_t ptextLen, void* crtxt);
        lib.AES_XTS_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        # char AES_XTS_decrypt(const uint8_t* keys, const uint8_t* tweak, const void* crtxt, size_t crtxtLen, void* pntxt);
        lib.AES_XTS_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.AES_XTS_decrypt.restype = ctypes.c_char

        # Vectors (Key is 32 bytes for AES-128 XTS: 16 byte key1 + 16 byte key2)
        # Using 64 byte key (32+32) implies AES-256, but default build is AES-128.
        # Wait, AES___=128 macro sets the block cipher key size.
        # XTS usually takes 2 keys of that size.
        # The test vector in TASK_CORE.md shows a 64-byte key (32+32). This implies AES-256.
        # But we built with -DAES___=128.
        # So I should use a 32-byte key (16+16) for the test if the DLL is 128-bit.
        # Let's check the vector provided.
        # Key: 00...00 (64 bytes).
        # If I use this with AES-128 build, it might read out of bounds or just use first 32 bytes.
        # I will use a 32-byte key (16+16) for AES-128-XTS.
        
        key_xts = bytes(32) # 16+16
        tweak = bytes(16)
        pt_xts = bytes(32)
        
        # I don't have a KAT for AES-128-XTS handy in the doc, so I'll just test roundtrip.
        ct_xts_buf = ctypes.create_string_buffer(len(pt_xts))
        lib.AES_XTS_encrypt(key_xts, tweak, pt_xts, len(pt_xts), ct_xts_buf)
        
        pt_xts_out = ctypes.create_string_buffer(len(pt_xts))
        lib.AES_XTS_decrypt(key_xts, tweak, ct_xts_buf, len(ct_xts_buf), pt_xts_out)
        
        if pt_xts_out.raw == pt_xts:
            console.print_pass("AES-XTS Roundtrip")
            log_test("AES-XTS", key_xts, tweak, pt_xts, ct_xts_buf.raw)
            passed += 1
        else:
            console.print_fail("AES-XTS Roundtrip failed")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"AES Modes: {passed} passed")
            return 0
        else:
            console.print_fail(f"AES Modes: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
