import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import console

def main():
    """Run tests for macs.dll."""
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'core', 'macs.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        def log_test(name, key, msg, mac):
            console.log_data(f"{name}.key", key.hex() if key else "None")
            if msg: console.log_data(f"{name}.msg", msg.hex())
            if mac: console.log_data(f"{name}.mac", mac.hex())

        # ---------------------------------------------------------
        # AES-CMAC Test (NIST SP 800-38B)
        # ---------------------------------------------------------
        console.print_step("Testing AES-CMAC")
        
        # void AES_CMAC(const uint8_t* key, const void* data, size_t dataSize, block_t mac);
        lib.AES_CMAC.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
        
        key_cmac = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg_cmac = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_mac = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
        
        mac_buf = ctypes.create_string_buffer(16)
        lib.AES_CMAC(key_cmac, msg_cmac, len(msg_cmac), mac_buf)
        
        if mac_buf.raw == expected_mac:
            console.print_pass("AES-CMAC KAT")
            log_test("AES-CMAC", key_cmac, msg_cmac, mac_buf.raw)
            passed += 1
        else:
            console.print_fail("AES-CMAC KAT mismatch")
            console.print_fail(f"Expected: {expected_mac.hex()}")
            console.print_fail(f"Actual:   {mac_buf.raw.hex()}")
            failed += 1

        # ---------------------------------------------------------
        # HMAC-SHA256 Test (RFC 4231)
        # ---------------------------------------------------------
        console.print_step("Testing HMAC-SHA256")
        
        # void pqc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
        lib.pqc_hmac_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        
        key_hmac = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        msg_hmac = b"Hi There"
        expected_hmac = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        
        hmac_buf = ctypes.create_string_buffer(32)
        lib.pqc_hmac_sha256(key_hmac, len(key_hmac), msg_hmac, len(msg_hmac), hmac_buf)
        
        if hmac_buf.raw == expected_hmac:
            console.print_pass("HMAC-SHA256 KAT")
            log_test("HMAC-SHA256", key_hmac, msg_hmac, hmac_buf.raw)
            passed += 1
        else:
            console.print_fail("HMAC-SHA256 KAT mismatch")
            console.print_fail(f"Expected: {expected_hmac.hex()}")
            console.print_fail(f"Actual:   {hmac_buf.raw.hex()}")
            failed += 1

        # ---------------------------------------------------------
        # SipHash Test
        # ---------------------------------------------------------
        console.print_step("Testing SipHash")
        
        # int siphash(const void *in, size_t inlen, const void *k, uint8_t *out, size_t outlen);
        lib.siphash.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        
        key_sip = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        msg_sip = bytes.fromhex("000102030405060708090a0b0c0d0e")
        expected_sip = bytes.fromhex("a129ca6149be45e5")[::-1] # 8 bytes (Little Endian)
        
        sip_buf = ctypes.create_string_buffer(8)
        lib.siphash(msg_sip, len(msg_sip), key_sip, sip_buf, 8)
        
        if sip_buf.raw == expected_sip:
            console.print_pass("SipHash KAT")
            log_test("SipHash", key_sip, msg_sip, sip_buf.raw)
            passed += 1
        else:
            console.print_fail("SipHash KAT mismatch")
            console.print_fail(f"Expected: {expected_sip.hex()}")
            console.print_fail(f"Actual:   {sip_buf.raw.hex()}")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"MACs: {passed} passed")
            return 0
        else:
            console.print_fail(f"MACs: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
