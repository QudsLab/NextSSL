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

        # ── Profile / Config (GPT_CONV_012: "profiles over algorithm shopping") ──

        # variant
        try:
            lib.nextssl_variant.argtypes = []
            lib.nextssl_variant.restype = ctypes.c_char_p
            v = lib.nextssl_variant()
            if v != b"lite":
                console.print_fail(f"nextssl_variant expected b'lite', got {v}")
                failed += 1
            else:
                console.print_pass("nextssl_variant() == 'lite' OK")
        except Exception as e:
            console.print_fail(f"nextssl_variant failed: {e}")
            failed += 1

        # init with MODERN profile (profile=0), then check security level
        try:
            lib.nextssl_init.argtypes = [ctypes.c_int]
            lib.nextssl_init.restype = ctypes.c_int
            lib.nextssl_security_level.argtypes = []
            lib.nextssl_security_level.restype = ctypes.c_char_p

            ret = lib.nextssl_init(0)  # 0 = MODERN
            if ret != 0:
                console.print_fail(f"nextssl_init(MODERN) failed (ret={ret})")
                failed += 1
            else:
                level = lib.nextssl_security_level()
                if level != b"modern-safe":
                    console.print_fail(f"nextssl_security_level expected b'modern-safe', got {level}")
                    failed += 1
                else:
                    console.print_pass("nextssl_init(MODERN) + security_level OK")
        except Exception as e:
            console.print_fail(f"nextssl_init/security_level failed: {e}")
            failed += 1

        # second call to init must not crash (already-init is silently accepted)
        try:
            ret2 = lib.nextssl_init(0)
            if ret2 != 0:
                console.print_fail(f"nextssl_init second call returned {ret2} (should be 0)")
                failed += 1
            else:
                console.print_pass("nextssl_init second call idempotent OK")
        except Exception as e:
            console.print_fail(f"nextssl_init idempotent failed: {e}")
            failed += 1

        # has_algorithm - known present
        try:
            lib.nextssl_has_algorithm.argtypes = [ctypes.c_char_p]
            lib.nextssl_has_algorithm.restype = ctypes.c_int
            known = [b"SHA-256", b"AES-256-GCM", b"ChaCha20-Poly1305",
                     b"Argon2id", b"X25519", b"ML-KEM-1024", b"Ed25519", b"ML-DSA-87"]
            ok = all(lib.nextssl_has_algorithm(a) == 1 for a in known)
            if not ok:
                console.print_fail("nextssl_has_algorithm: some known algo returned 0")
                failed += 1
            else:
                console.print_pass("nextssl_has_algorithm (known algos) OK")
        except Exception as e:
            console.print_fail(f"nextssl_has_algorithm known failed: {e}")
            failed += 1

        # has_algorithm - unknown must return 0
        try:
            if lib.nextssl_has_algorithm(b"GARBAGE-99") != 0:
                console.print_fail("nextssl_has_algorithm('GARBAGE-99') should return 0")
                failed += 1
            else:
                console.print_pass("nextssl_has_algorithm (unknown algo) returns 0 OK")
        except Exception as e:
            console.print_fail(f"nextssl_has_algorithm unknown failed: {e}")
            failed += 1

        # hash_ex with SHA-512
        try:
            lib.nextssl_hash_ex.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_hash_ex.restype = ctypes.c_int
            out512 = ctypes.create_string_buffer(64)
            ret = lib.nextssl_hash_ex(b"SHA-512", b"abc", 3, out512)
            expected512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            if ret != 0 or out512.raw.hex() != expected512:
                console.print_fail(f"nextssl_hash_ex SHA-512 mismatch (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_hash_ex (SHA-512) OK")
        except Exception as e:
            console.print_fail(f"nextssl_hash_ex failed: {e}")
            failed += 1

        # encrypt_ex / decrypt_ex with ChaCha20-Poly1305
        try:
            lib.nextssl_encrypt_ex.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_encrypt_ex.restype = ctypes.c_int
            lib.nextssl_decrypt_ex.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_decrypt_ex.restype = ctypes.c_int

            algo  = b"ChaCha20-Poly1305"
            key   = bytes(range(32))
            nonce = bytes(range(12))
            pt    = b"chacha roundtrip"
            ct_ex = ctypes.create_string_buffer(len(pt) + 16)
            ret   = lib.nextssl_encrypt_ex(algo, key, nonce, pt, len(pt), ct_ex)
            if ret != 0:
                console.print_fail(f"nextssl_encrypt_ex ChaCha failed (ret={ret})")
                failed += 1
            else:
                pt_ex = ctypes.create_string_buffer(len(pt))
                ret2  = lib.nextssl_decrypt_ex(algo, key, nonce, ct_ex.raw, len(ct_ex), pt_ex)
                if ret2 != 0 or pt_ex.raw != pt:
                    console.print_fail(f"nextssl_decrypt_ex ChaCha failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_encrypt_ex/decrypt_ex (ChaCha20-Poly1305) OK")
        except Exception as e:
            console.print_fail(f"nextssl_encrypt_ex/decrypt_ex failed: {e}")
            failed += 1

        # version string
        try:
            lib.nextssl_version.argtypes = []
            lib.nextssl_version.restype = ctypes.c_char_p
            ver = lib.nextssl_version()
            if not ver or b"lite" not in ver:
                console.print_fail(f"nextssl_version unexpected: {ver}")
                failed += 1
            else:
                console.print_pass(f"nextssl_version() = {ver.decode()} OK")
        except Exception as e:
            console.print_fail(f"nextssl_version failed: {e}")
            failed += 1

        # ── Profile dispatch: PQC profile → hash() must use BLAKE3
        # (BLAKE3 has no fixed KAT without knowing the internal iter count,
        #  so we simply call hash() after nextssl_init(2) and confirm non-crash
        #  and non-SHA-256 output — SHA-256("abc") ends in ...015ad)
        try:
            lib.nextssl_cleanup.argtypes = []
            lib.nextssl_cleanup.restype = None
            lib.nextssl_cleanup()                    # reset to uninitialised
            ret_pqc = lib.nextssl_init(2)            # 2 = PQC
            if ret_pqc != 0:
                console.print_fail(f"nextssl_init(PQC) failed (ret={ret_pqc})")
                failed += 1
            else:
                level_pqc = lib.nextssl_security_level()
                if level_pqc != b"post-quantum":
                    console.print_fail(f"nextssl_security_level(PQC) expected b'post-quantum', got {level_pqc}")
                    failed += 1
                else:
                    out_pqc = ctypes.create_string_buffer(32)
                    r = lib.nextssl_hash(b"abc", 3, out_pqc)
                    sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    if r != 0:
                        console.print_fail(f"nextssl_hash under PQC profile failed (ret={r})")
                        failed += 1
                    elif out_pqc.raw.hex() == sha256_abc:
                        console.print_fail("PQC profile hash returned SHA-256 — expected BLAKE3 dispatch")
                        failed += 1
                    else:
                        console.print_pass("nextssl_init(PQC) + hash BLAKE3 dispatch OK")
        except Exception as e:
            console.print_fail(f"PQC profile dispatch test failed: {e}")
            failed += 1

        # ── Custom profile init ──
        try:
            # nextssl_custom_profile_t: 5 int fields + const char *name
            class NextsslCustomProfile(ctypes.Structure):
                _fields_ = [
                    ("hash", ctypes.c_int),    # 0 = SHA-256
                    ("aead", ctypes.c_int),    # 0 = AES-256-GCM
                    ("kdf",  ctypes.c_int),    # 1 = Argon2id  (kdf=0 = HKDF-SHA256 is unimplemented)
                    ("sign", ctypes.c_int),    # 0 = Ed25519
                    ("kem",  ctypes.c_int),    # 1 = ML-KEM-1024 (lite)
                    ("name", ctypes.c_char_p), # optional label (NULL → "Custom")
                ]

            lib.nextssl_cleanup.argtypes = []
            lib.nextssl_cleanup.restype = None
            lib.nextssl_cleanup()
            lib.nextssl_init_custom.argtypes = [ctypes.POINTER(NextsslCustomProfile)]
            lib.nextssl_init_custom.restype = ctypes.c_int
            lib.nextssl_security_level.argtypes = []
            lib.nextssl_security_level.restype = ctypes.c_char_p

            prof = NextsslCustomProfile(hash=0, aead=0, kdf=1, sign=0, kem=1, name=None)
            ret_c = lib.nextssl_init_custom(ctypes.byref(prof))
            if ret_c != 0:
                console.print_fail(f"nextssl_init_custom failed (ret={ret_c})")
                failed += 1
            else:
                lvl = lib.nextssl_security_level()
                if lvl != b"custom":
                    console.print_fail(f"nextssl_security_level after custom init expected b'custom', got {lvl}")
                    failed += 1
                else:
                    console.print_pass("nextssl_init_custom + security_level 'custom' OK")
        except Exception as e:
            console.print_fail(f"nextssl_init_custom failed: {e}")
            failed += 1

        # ── Root / explicit-algorithm functions ──

        # root_sha256 KAT
        try:
            lib.nextssl_root_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_root_sha256.restype = ctypes.c_int
            out_r = ctypes.create_string_buffer(32)
            ret = lib.nextssl_root_sha256(b"abc", 3, out_r)
            expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            if ret != 0 or out_r.raw.hex() != expected:
                console.print_fail(f"nextssl_root_sha256 mismatch (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_root_sha256 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_sha256 failed: {e}")
            failed += 1

        # root_blake3 (32-byte output, "abc" known via BLAKE3 reference)
        try:
            lib.nextssl_root_blake3.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t
            ]
            lib.nextssl_root_blake3.restype = ctypes.c_int
            out_b3 = ctypes.create_string_buffer(32)
            ret = lib.nextssl_root_blake3(b"abc", 3, out_b3, 32)
            b3_abc = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
            if ret != 0 or out_b3.raw.hex() != b3_abc:
                console.print_fail(f"nextssl_root_blake3 KAT mismatch (ret={ret}), got {out_b3.raw.hex()}")
                failed += 1
            else:
                console.print_pass("nextssl_root_blake3 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_blake3 failed: {e}")
            failed += 1

        # root_aes256gcm_encrypt / decrypt round-trip
        try:
            lib.nextssl_root_aes256gcm_encrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_root_aes256gcm_encrypt.restype = ctypes.c_int
            lib.nextssl_root_aes256gcm_decrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_root_aes256gcm_decrypt.restype = ctypes.c_int

            key   = bytes(range(32))
            nonce = bytes(range(12))
            pt    = b"root aes-gcm test"
            ct_r  = ctypes.create_string_buffer(len(pt) + 16)
            ret   = lib.nextssl_root_aes256gcm_encrypt(key, nonce, pt, len(pt), ct_r)
            if ret != 0:
                console.print_fail(f"nextssl_root_aes256gcm_encrypt failed (ret={ret})")
                failed += 1
            else:
                pt_r2 = ctypes.create_string_buffer(len(pt))
                ret2  = lib.nextssl_root_aes256gcm_decrypt(key, nonce, ct_r.raw, len(ct_r), pt_r2)
                if ret2 != 0 or pt_r2.raw[:len(pt)] != pt:
                    console.print_fail(f"nextssl_root_aes256gcm_decrypt round-trip failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_root_aes256gcm encrypt/decrypt round-trip OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_aes256gcm round-trip failed: {e}")
            failed += 1

        # root_chacha20 round-trip
        try:
            lib.nextssl_root_chacha20_encrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_root_chacha20_encrypt.restype = ctypes.c_int
            lib.nextssl_root_chacha20_decrypt.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
            ]
            lib.nextssl_root_chacha20_decrypt.restype = ctypes.c_int

            key   = bytes(range(32))
            nonce = bytes(range(12))
            pt    = b"root chacha test"
            ct_c  = ctypes.create_string_buffer(len(pt) + 16)
            ret   = lib.nextssl_root_chacha20_encrypt(key, nonce, pt, len(pt), ct_c)
            if ret != 0:
                console.print_fail(f"nextssl_root_chacha20_encrypt failed (ret={ret})")
                failed += 1
            else:
                pt_c2 = ctypes.create_string_buffer(len(pt))
                ret2  = lib.nextssl_root_chacha20_decrypt(key, nonce, ct_c.raw, len(ct_c), pt_c2)
                if ret2 != 0 or pt_c2.raw[:len(pt)] != pt:
                    console.print_fail(f"nextssl_root_chacha20_decrypt round-trip failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_root_chacha20 encrypt/decrypt round-trip OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_chacha20 round-trip failed: {e}")
            failed += 1

        # root_ed25519 keygen / sign / verify
        try:
            lib.nextssl_root_ed25519_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_ed25519_keygen.restype   = ctypes.c_int
            lib.nextssl_root_ed25519_sign.argtypes    = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_ed25519_sign.restype     = ctypes.c_int
            lib.nextssl_root_ed25519_verify.argtypes  = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_ed25519_verify.restype   = ctypes.c_int

            pk_e  = ctypes.create_string_buffer(32)
            sk_e  = ctypes.create_string_buffer(64)
            sig_e = ctypes.create_string_buffer(64)
            msg_e = b"root ed25519 test"
            lib.nextssl_root_ed25519_keygen(pk_e, sk_e)
            ret_s = lib.nextssl_root_ed25519_sign(sig_e, msg_e, len(msg_e), sk_e.raw)
            ret_v = lib.nextssl_root_ed25519_verify(sig_e.raw, msg_e, len(msg_e), pk_e.raw)
            if ret_s != 0 or ret_v != 1:
                console.print_fail(f"nextssl_root_ed25519 sign/verify failed (s={ret_s}, v={ret_v})")
                failed += 1
            else:
                console.print_pass("nextssl_root_ed25519 keygen/sign/verify OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_ed25519 failed: {e}")
            failed += 1

        # root_mldsa87 keygen / sign / verify (pk=2592 sk=4896 sig_max=4627)
        try:
            lib.nextssl_root_mldsa87_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_mldsa87_keygen.restype   = ctypes.c_int
            lib.nextssl_root_mldsa87_sign.argtypes    = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa87_sign.restype     = ctypes.c_int
            lib.nextssl_root_mldsa87_verify.argtypes  = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa87_verify.restype   = ctypes.c_int

            pk_d  = ctypes.create_string_buffer(2592)
            sk_d  = ctypes.create_string_buffer(4896)
            sig_d = ctypes.create_string_buffer(4627)
            sig_len = ctypes.c_size_t(4627)
            msg_d = b"root mldsa87 test"
            lib.nextssl_root_mldsa87_keygen(pk_d, sk_d)
            ret_s = lib.nextssl_root_mldsa87_sign(sig_d, ctypes.byref(sig_len), msg_d, len(msg_d), sk_d.raw)
            ret_v = lib.nextssl_root_mldsa87_verify(sig_d.raw, sig_len.value, msg_d, len(msg_d), pk_d.raw)
            if ret_s != 0 or ret_v != 1:
                console.print_fail(f"nextssl_root_mldsa87 failed (s={ret_s}, v={ret_v})")
                failed += 1
            else:
                console.print_pass("nextssl_root_mldsa87 keygen/sign/verify OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_mldsa87 failed: {e}")
            failed += 1

        # root_argon2id
        try:
            lib.nextssl_root_argon2id.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t
            ]
            lib.nextssl_root_argon2id.restype = ctypes.c_int
            out_a = ctypes.create_string_buffer(32)
            ret   = lib.nextssl_root_argon2id(b"password", 8, b"saltsalt", 8, out_a, 32)
            if ret != 0 or out_a.raw == bytes(32):
                console.print_fail(f"nextssl_root_argon2id failed (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_root_argon2id OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_argon2id failed: {e}")
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
