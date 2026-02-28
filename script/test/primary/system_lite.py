import ctypes
import os
import sys
from script.core import Config, console

def main():
    try:
        config = Config()
        dll_path = os.path.join(config.bin_dir, 'primary', f"main_lite{config.get_shared_lib_ext()}")

        console.print_step(f"Loading {dll_path}")
        if not os.path.exists(dll_path):
            console.print_fail(f"DLL not found: {dll_path}")
            return 1

        lib = ctypes.CDLL(dll_path)
        console.print_pass("DLL Loaded")

        failed = 0

        # ── Hash ──
        try:
            lib.nextssl_hash.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_hash.restype = ctypes.c_int
            out = ctypes.create_string_buffer(32)
            ret = lib.nextssl_hash(b"abc", 3, out)
            expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            if ret != 0 or out.raw.hex() != expected:
                console.print_fail(f"nextssl_hash mismatch (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_hash (SHA-256) OK")
        except Exception as e:
            console.print_fail(f"nextssl_hash failed: {e}")
            failed += 1

        # ── Encrypt / Decrypt ──
        try:
            lib.nextssl_encrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_encrypt.restype = ctypes.c_int
            lib.nextssl_decrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_decrypt.restype = ctypes.c_int

            key   = bytes(range(32))
            nonce = bytes(range(12))
            pt    = b"hello lite world"
            ct_buf = ctypes.create_string_buffer(len(pt) + 16)
            ret = lib.nextssl_encrypt(key, nonce, pt, len(pt), ct_buf)
            if ret != 0:
                console.print_fail(f"nextssl_encrypt failed (ret={ret})")
                failed += 1
            else:
                pt_buf = ctypes.create_string_buffer(len(pt))
                ret2 = lib.nextssl_decrypt(key, nonce, ct_buf.raw, len(ct_buf), pt_buf)
                if ret2 != 0 or pt_buf.raw != pt:
                    console.print_fail(f"nextssl_decrypt failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_encrypt/decrypt (AES-256-GCM) OK")
        except Exception as e:
            console.print_fail(f"nextssl_encrypt/decrypt failed: {e}")
            failed += 1

        # ── Password Hash / Verify ──
        try:
            lib.nextssl_password_hash.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_void_p
            ]
            lib.nextssl_password_hash.restype = ctypes.c_int
            lib.nextssl_password_verify.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_char_p
            ]
            lib.nextssl_password_verify.restype = ctypes.c_int

            password = b"secretpassword"
            salt     = bytes(range(16))
            h_buf    = ctypes.create_string_buffer(32)
            ret = lib.nextssl_password_hash(password, len(password), salt, h_buf)
            if ret != 0:
                console.print_fail(f"nextssl_password_hash failed (ret={ret})")
                failed += 1
            else:
                ret2 = lib.nextssl_password_verify(password, len(password), salt, h_buf.raw)
                if ret2 != 0:
                    console.print_fail(f"nextssl_password_verify failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_password_hash/verify (Argon2id) OK")
        except Exception as e:
            console.print_fail(f"nextssl_password failed: {e}")
            failed += 1

        # ── Classical Key Exchange (X25519) ──
        try:
            lib.nextssl_keygen.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            lib.nextssl_keygen.restype = ctypes.c_int
            lib.nextssl_keyexchange.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int
            ]
            lib.nextssl_keyexchange.restype = ctypes.c_int

            pk_a = ctypes.create_string_buffer(32)
            sk_a = ctypes.create_string_buffer(32)
            pk_b = ctypes.create_string_buffer(32)
            sk_b = ctypes.create_string_buffer(32)
            lib.nextssl_keygen(pk_a, sk_a, 0)
            lib.nextssl_keygen(pk_b, sk_b, 0)

            ss_a = ctypes.create_string_buffer(32)
            ss_b = ctypes.create_string_buffer(32)
            lib.nextssl_keyexchange(sk_a.raw, pk_b.raw, ss_a, None, 0)
            lib.nextssl_keyexchange(sk_b.raw, pk_a.raw, ss_b, None, 0)
            if ss_a.raw != ss_b.raw:
                console.print_fail("X25519 shared secrets do not match")
                failed += 1
            else:
                console.print_pass("nextssl_keygen/keyexchange (X25519) OK")
        except Exception as e:
            console.print_fail(f"nextssl X25519 keyexchange failed: {e}")
            failed += 1

        # ── Classical Signature (Ed25519) ──
        try:
            lib.nextssl_sign_keygen.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            lib.nextssl_sign_keygen.restype = ctypes.c_int
            lib.nextssl_sign.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int
            ]
            lib.nextssl_sign.restype = ctypes.c_int
            lib.nextssl_verify.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int
            ]
            lib.nextssl_verify.restype = ctypes.c_int

            pk = ctypes.create_string_buffer(32)
            sk = ctypes.create_string_buffer(64)
            lib.nextssl_sign_keygen(pk, sk, 0)
            msg = b"test message"
            sig = ctypes.create_string_buffer(64)
            ret = lib.nextssl_sign(msg, len(msg), sk.raw, sig, 0)
            if ret != 0:
                console.print_fail(f"nextssl_sign failed (ret={ret})")
                failed += 1
            else:
                ret2 = lib.nextssl_verify(msg, len(msg), sig.raw, pk.raw, 0)
                if ret2 != 0:
                    console.print_fail(f"nextssl_verify failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_sign/verify (Ed25519) OK")
        except Exception as e:
            console.print_fail(f"nextssl Ed25519 sign/verify failed: {e}")
            failed += 1

        # ── PoW ──
        try:
            lib.nextssl_pow_solve.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p
            ]
            lib.nextssl_pow_solve.restype = ctypes.c_int
            lib.nextssl_pow_verify.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32,
                ctypes.c_uint64, ctypes.c_char_p
            ]
            lib.nextssl_pow_verify.restype = ctypes.c_int

            challenge = b"litechallenge1234567890123456789"[:32]
            difficulty = ctypes.c_uint32(1)  # very low for test speed
            nonce_out  = ctypes.c_uint64(0)
            hash_out   = ctypes.create_string_buffer(32)
            ret = lib.nextssl_pow_solve(challenge, len(challenge), difficulty, ctypes.byref(nonce_out), hash_out)
            if ret != 0:
                console.print_fail(f"nextssl_pow_solve failed (ret={ret})")
                failed += 1
            else:
                ret2 = lib.nextssl_pow_verify(challenge, len(challenge), difficulty, nonce_out, hash_out.raw)
                if ret2 != 0:
                    console.print_fail(f"nextssl_pow_verify failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_pow_solve/verify OK")
        except Exception as e:
            console.print_fail(f"nextssl_pow failed: {e}")
            failed += 1

        if failed == 0:
            console.print_pass("Lite unified DLL OK")
            return 0
        console.print_fail(f"Lite unified DLL failed: {failed} checks")
        return 1
    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
