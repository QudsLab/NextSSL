import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import console

def main():
    """Run tests for ecc.dll."""
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'core', 'ecc.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        passed = 0
        failed = 0

        def log_test(name, key, msg, sig):
            console.log_data(f"{name}.key", key.hex() if key else "None")
            if msg: console.log_data(f"{name}.msg", msg.hex())
            if sig: console.log_data(f"{name}.sig", sig.hex())

        # ---------------------------------------------------------
        # Ed25519 Test (RFC 8032)
        # ---------------------------------------------------------
        console.print_step("Testing Ed25519")
        
        # int ed25519_create_seed(unsigned char *seed);
        # void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
        # void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
        # int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);

        lib.ed25519_create_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.ed25519_sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        lib.ed25519_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.ed25519_verify.restype = ctypes.c_int

        # Vector
        sk_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        expected_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        expected_sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        
        pk_buf = ctypes.create_string_buffer(32)
        sk_buf = ctypes.create_string_buffer(64) # Ed25519 SK is often 64 bytes (seed + pk)
        
        lib.ed25519_create_keypair(pk_buf, sk_buf, sk_seed)
        
        if pk_buf.raw == expected_pk:
            console.print_pass("Ed25519 Keypair Gen KAT")
            passed += 1
        else:
            console.print_fail("Ed25519 Keypair Gen KAT mismatch")
            console.print_fail(f"Expected: {expected_pk.hex()}")
            console.print_fail(f"Actual:   {pk_buf.raw.hex()}")
            failed += 1

        msg = b""
        sig_buf = ctypes.create_string_buffer(64)
        lib.ed25519_sign(sig_buf, msg, len(msg), pk_buf, sk_buf)
        
        if sig_buf.raw == expected_sig:
            console.print_pass("Ed25519 Sign KAT")
            log_test("Ed25519", expected_pk, msg, sig_buf.raw)
            passed += 1
        else:
            console.print_fail("Ed25519 Sign KAT mismatch")
            console.print_fail(f"Expected: {expected_sig.hex()}")
            console.print_fail(f"Actual:   {sig_buf.raw.hex()}")
            failed += 1
            
        # Verify
        if lib.ed25519_verify(sig_buf, msg, len(msg), pk_buf) == 1:
            console.print_pass("Ed25519 Verify")
            passed += 1
        else:
            console.print_fail("Ed25519 Verify failed")
            failed += 1

        # ---------------------------------------------------------
        # X25519 Test (RFC 7748)
        # ---------------------------------------------------------
        console.print_step("Testing X25519")
        
        # void curve25519(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
        lib.curve25519.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        
        alice_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        expected_shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        
        shared_buf = ctypes.create_string_buffer(32)
        lib.curve25519(shared_buf, bob_pk, alice_sk)
        
        if shared_buf.raw == expected_shared:
            console.print_pass("X25519 KAT")
            log_test("X25519", alice_sk, bob_pk, shared_buf.raw)
            passed += 1
        else:
            console.print_fail("X25519 KAT mismatch")
            console.print_fail(f"Expected: {expected_shared.hex()}")
            console.print_fail(f"Actual:   {shared_buf.raw.hex()}")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"ECC: {passed} passed")
            return 0
        else:
            console.print_fail(f"ECC: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
