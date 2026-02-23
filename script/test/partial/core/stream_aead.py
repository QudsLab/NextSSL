import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, console

def main():
    """Run tests for stream_aead.dll."""
    try:
        config = Config()
        DLL_PATH = config.get_lib_path('partial', 'stream_aead', 'core')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        def log_test(name, key, iv, pt, ct, tag=None):
            console.log_data(f"{name}.key", key.hex() if key else "None")
            if iv: console.log_data(f"{name}.iv", iv.hex())
            if pt: console.log_data(f"{name}.pt", pt.hex())
            if ct: console.log_data(f"{name}.ct", ct.hex())
            if tag: console.log_data(f"{name}.tag", tag.hex())

        # ---------------------------------------------------------
        # ChaCha20-Poly1305 Test (RFC 8439)
        # ---------------------------------------------------------
        console.print_step("Testing ChaCha20-Poly1305")
        
        # void ChaCha20_Poly1305_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* pntxt, size_t ptextLen, void* crtxt);
        lib.ChaCha20_Poly1305_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        
        # char ChaCha20_Poly1305_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* crtxt, size_t crtxtLen, void* pntxt);
        lib.ChaCha20_Poly1305_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.ChaCha20_Poly1305_decrypt.restype = ctypes.c_byte

        # Vectors
        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("070000004041424344454647")
        pt = bytes.fromhex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        expected_ct_full = bytes.fromhex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" + "1ae10b594f09e26a7e902ecbd0600691")
        
        # Note: The expected CT usually includes the tag at the end for Poly1305 AEAD.
        # My implementation likely appends the tag.
        
        ct_buf = ctypes.create_string_buffer(len(pt) + 16)
        
        lib.ChaCha20_Poly1305_encrypt(key, nonce, aad, len(aad), pt, len(pt), ct_buf)
        
        if ct_buf.raw == expected_ct_full:
            console.print_pass("ChaCha20-Poly1305 Encrypt KAT")
            print(f"       Ciphertext: {ct_buf.raw.hex()}")
            log_test("ChaCha20-Poly1305", key, nonce, pt, ct_buf.raw)
            passed += 1
        else:
            console.print_fail("ChaCha20-Poly1305 Encrypt KAT mismatch")
            console.print_fail(f"Expected: {expected_ct_full.hex()}")
            console.print_fail(f"Actual:   {ct_buf.raw.hex()}")
            failed += 1

        # Decrypt
        pt_out = ctypes.create_string_buffer(len(pt))
        ret = lib.ChaCha20_Poly1305_decrypt(key, nonce, aad, len(aad), ct_buf, len(ct_buf), pt_out)
        
        if ret == 0 and pt_out.raw == pt:
            console.print_pass("ChaCha20-Poly1305 Decrypt Roundtrip")
            passed += 1
        else:
            console.print_fail("ChaCha20-Poly1305 Decrypt failed")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"Stream AEAD: {passed} passed")
            return 0
        else:
            console.print_fail(f"Stream AEAD: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
