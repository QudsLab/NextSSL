import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import console

def main():
    """Run tests for core_ecc_main.dll (Base Tier)."""
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'base', 'core_ecc_main.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        # ---------------------------------------------------------
        # 1. Ed25519 Test
        # ---------------------------------------------------------
        console.print_step("Verifying Ed25519 symbol")
        lib.ed25519_create_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        
        sk_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        expected_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        
        pk_buf = ctypes.create_string_buffer(32)
        sk_buf = ctypes.create_string_buffer(64)
        
        lib.ed25519_create_keypair(pk_buf, sk_buf, sk_seed)
        
        if pk_buf.raw == expected_pk:
            console.print_pass("Ed25519 OK")
            console.log_data("Ed25519.sk_seed", sk_seed.hex())
            console.log_data("Ed25519.pk", pk_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("Ed25519 Failed")
            failed += 1

        # ---------------------------------------------------------
        # 2. X25519 Test
        # ---------------------------------------------------------
        console.print_step("Verifying X25519 symbol")
        lib.curve25519.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        
        alice_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        expected_shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        
        shared_buf = ctypes.create_string_buffer(32)
        lib.curve25519(shared_buf, bob_pk, alice_sk)
        
        if shared_buf.raw == expected_shared:
            console.print_pass("X25519 OK")
            console.log_data("X25519.alice_sk", alice_sk.hex())
            console.log_data("X25519.bob_pk", bob_pk.hex())
            console.log_data("X25519.shared", shared_buf.raw.hex())
            passed += 1
        else:
            console.print_fail("X25519 Failed")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"Core ECC Base: {passed} passed")
            return 0
        else:
            console.print_fail(f"Core ECC Base: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
