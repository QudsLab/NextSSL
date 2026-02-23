import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, console

def main():
    """Run tests for core_mac_main.dll (Base Tier)."""
    try:
        config = Config()
        DLL_PATH = config.get_lib_path('base', 'core_mac_main')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        # ---------------------------------------------------------
        # 1. AES-CMAC Test
        # ---------------------------------------------------------
        console.print_step("Verifying AES-CMAC symbol")
        lib.AES_CMAC.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
        
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_mac = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
        
        mac_buf = ctypes.create_string_buffer(16)
        lib.AES_CMAC(key, msg, len(msg), mac_buf)
        
        if mac_buf.raw == expected_mac:
            console.print_pass("AES-CMAC OK")
            print(f"       MAC:        {mac_buf.raw.hex()}")
            console.log_data("AES-CMAC.key", key.hex())
            console.log_data("AES-CMAC.msg", msg.hex())
            console.log_data("AES-CMAC.mac", mac_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("AES-CMAC Failed")
            failed += 1

        # ---------------------------------------------------------
        # 2. HMAC-SHA256 Test
        # ---------------------------------------------------------
        console.print_step("Verifying HMAC-SHA256 symbol")
        lib.pqc_hmac_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        
        key_hmac = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        msg_hmac = b"Hi There"
        expected_hmac = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        
        hmac_buf = ctypes.create_string_buffer(32)
        lib.pqc_hmac_sha256(key_hmac, len(key_hmac), msg_hmac, len(msg_hmac), hmac_buf)
        
        if hmac_buf.raw == expected_hmac:
            console.print_pass("HMAC-SHA256 OK")
            print(f"       HMAC:       {hmac_buf.raw.hex()}")
            console.log_data("HMAC-SHA256.key", key_hmac.hex())
            console.log_data("HMAC-SHA256.msg", msg_hmac.hex())
            console.log_data("HMAC-SHA256.mac", hmac_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("HMAC-SHA256 Failed")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"Core MAC Base: {passed} passed")
            return 0
        else:
            console.print_fail(f"Core MAC Base: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
