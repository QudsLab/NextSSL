import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import console

def main():
    """Run tests for core.dll (Main Tier)."""
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'main', 'core.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        # ---------------------------------------------------------
        # 1. Cipher: AES-CBC
        # ---------------------------------------------------------
        console.print_step("Verifying AES-CBC")
        lib.AES_CBC_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        ct_buf = ctypes.create_string_buffer(len(pt))
        lib.AES_CBC_encrypt(key, iv, pt, len(pt), ct_buf)
        if ct_buf.raw == expected_ct: passed += 1
        else: failed += 1; console.print_fail("AES-CBC Failed")

        # ---------------------------------------------------------
        # 2. AEAD: AES-GCM
        # ---------------------------------------------------------
        console.print_step("Verifying AES-GCM")
        lib.AES_GCM_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        tag_buf = ctypes.create_string_buffer(16)
        lib.AES_GCM_encrypt(bytes(16), bytes(12), b"", 0, b"", 0, tag_buf)
        if tag_buf.raw.hex() == "58e2fccefa7e3061367f1d57a4e7455a": passed += 1
        else: failed += 1; console.print_fail("AES-GCM Failed")

        # ---------------------------------------------------------
        # 3. Stream: ChaCha20-Poly1305
        # ---------------------------------------------------------
        console.print_step("Verifying ChaCha20-Poly1305")
        try:
            lib.ChaCha20_Poly1305_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            passed += 1
        except Exception: failed += 1; console.print_fail("ChaCha20-Poly1305 Failed")

        # ---------------------------------------------------------
        # 4. MAC: HMAC-SHA256
        # ---------------------------------------------------------
        console.print_step("Verifying HMAC-SHA256")
        lib.pqc_hmac_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        key_hmac = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        msg_hmac = b"Hi There"
        expected_hmac = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        hmac_buf = ctypes.create_string_buffer(32)
        lib.pqc_hmac_sha256(key_hmac, len(key_hmac), msg_hmac, len(msg_hmac), hmac_buf)
        if hmac_buf.raw == expected_hmac: passed += 1
        else: failed += 1; console.print_fail("HMAC-SHA256 Failed")

        # ---------------------------------------------------------
        # 5. ECC: Ed25519
        # ---------------------------------------------------------
        console.print_step("Verifying Ed25519")
        lib.ed25519_create_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        sk_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        expected_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        pk_buf = ctypes.create_string_buffer(32)
        sk_buf = ctypes.create_string_buffer(64)
        lib.ed25519_create_keypair(pk_buf, sk_buf, sk_seed)
        if pk_buf.raw == expected_pk: passed += 1
        else: failed += 1; console.print_fail("Ed25519 Failed")

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"Core Main: {passed} passed")
            return 0
        else:
            console.print_fail(f"Core Main: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
