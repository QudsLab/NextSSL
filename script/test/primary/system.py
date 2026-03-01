import ctypes
import os
import sys
from script.core import Config, console

def main():
    try:
        config = Config()
        dll_path = os.path.join(config.bin_dir, 'primary', f"main{config.get_shared_lib_ext()}")

        console.print_step(f"Loading {dll_path}")
        if not os.path.exists(dll_path):
            console.print_fail(f"DLL not found: {dll_path}")
            return 1

        lib = ctypes.CDLL(dll_path)
        console.print_pass("DLL Loaded")

        failed = 0

        # ── SHA-256 utility (base layer sanity) ──
        try:
            lib.nextssl_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            out = ctypes.create_string_buffer(32)
            lib.nextssl_sha256(b"abc", 3, out)
            if out.raw.hex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
                console.print_fail("SHA256 utility mismatch")
                failed += 1
            else:
                console.print_pass("SHA256 utility OK")
        except Exception as e:
            console.print_fail(f"SHA256 utility failed: {e}")
            failed += 1

        # ── DHCM ──
        try:
            lib.nextssl_dhcm_expected_trials.argtypes = [ctypes.c_int, ctypes.c_uint32]
            lib.nextssl_dhcm_expected_trials.restype = ctypes.c_double
            val = lib.nextssl_dhcm_expected_trials(1, 8)
            if val <= 0:
                console.print_fail("DHCM expected trials invalid")
                failed += 1
            else:
                console.print_pass("DHCM OK")
        except Exception as e:
            console.print_fail(f"DHCM failed: {e}")
            failed += 1

        # ── PoW symbols ──
        try:
            _ = lib.nextssl_pow_server_generate_challenge
            _ = lib.nextssl_pow_client_solve
            console.print_pass("PoW symbols OK")
        except Exception as e:
            console.print_fail(f"PoW symbols missing: {e}")
            failed += 1

        # ── PQC symbols ──
        try:
            _ = lib.pqc_mlkem512_keypair
            console.print_pass("PQC symbols OK")
        except Exception as e:
            console.print_fail(f"PQC symbols missing: {e}")
            failed += 1

        # ── AES-CBC (legacy cipher layer) ──
        try:
            lib.AES_CBC_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
            iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
            pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
            expected_ct = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
            ct_buf = ctypes.create_string_buffer(len(pt))
            lib.AES_CBC_encrypt(key, iv, pt, len(pt), ct_buf)
            if ct_buf.raw != expected_ct:
                console.print_fail("AES-CBC mismatch")
                failed += 1
            else:
                console.print_pass("AES-CBC OK")
        except Exception as e:
            console.print_fail(f"AES-CBC failed: {e}")
            failed += 1

        # ── Primary API: init + hash (profile-driven) ──
        try:
            lib.nextssl_init.argtypes = [ctypes.c_int]
            lib.nextssl_init.restype = ctypes.c_int
            lib.nextssl_hash.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_hash.restype = ctypes.c_int
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
                    out_h = ctypes.create_string_buffer(32)
                    ret_h = lib.nextssl_hash(b"abc", 3, out_h)
                    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    if ret_h != 0 or out_h.raw.hex() != expected:
                        console.print_fail(f"nextssl_hash SHA-256 mismatch (ret={ret_h})")
                        failed += 1
                    else:
                        console.print_pass("nextssl_init(MODERN) + nextssl_hash OK")
        except Exception as e:
            console.print_fail(f"nextssl_init/hash failed: {e}")
            failed += 1

        # ── Primary API: encrypt / decrypt ──
        try:
            lib.nextssl_encrypt.argtypes = [
                ctypes.c_char_p,           # key[32]
                ctypes.c_char_p,           # plaintext
                ctypes.c_size_t,           # plaintext_len
                ctypes.c_void_p,           # ciphertext out
                ctypes.POINTER(ctypes.c_size_t),  # &ciphertext_len
            ]
            lib.nextssl_encrypt.restype = ctypes.c_int
            lib.nextssl_decrypt.argtypes = [
                ctypes.c_char_p,           # key[32]
                ctypes.c_char_p,           # ciphertext
                ctypes.c_size_t,           # ciphertext_len
                ctypes.c_void_p,           # plaintext out
                ctypes.POINTER(ctypes.c_size_t),  # &plaintext_len
            ]
            lib.nextssl_decrypt.restype = ctypes.c_int

            key    = bytes(range(32))
            pt     = b"hello full world"
            ct_buf = ctypes.create_string_buffer(len(pt) + 28)  # 12 nonce + plen + 16 tag
            ct_len = ctypes.c_size_t(len(ct_buf))
            ret    = lib.nextssl_encrypt(key, pt, len(pt), ct_buf, ctypes.byref(ct_len))
            if ret != 0:
                console.print_fail(f"nextssl_encrypt failed (ret={ret})")
                failed += 1
            else:
                pt_buf = ctypes.create_string_buffer(len(pt))
                pt_len = ctypes.c_size_t(len(pt))
                ret2   = lib.nextssl_decrypt(key, ct_buf.raw[:ct_len.value], ct_len.value, pt_buf, ctypes.byref(pt_len))
                if ret2 != 0 or pt_buf.raw[:len(pt)] != pt:
                    console.print_fail(f"nextssl_decrypt failed (ret={ret2})")
                    failed += 1
                else:
                    console.print_pass("nextssl_encrypt/decrypt round-trip OK")
        except Exception as e:
            console.print_fail(f"nextssl_encrypt/decrypt failed: {e}")
            failed += 1

        # ── Custom profile init ──
        try:
            class NextsslCustomProfile(ctypes.Structure):
                _fields_ = [
                    ("hash", ctypes.c_int),    # 0 = SHA-256
                    ("aead", ctypes.c_int),    # 1 = ChaCha20-Poly1305
                    ("kdf",  ctypes.c_int),    # 1 = Argon2id  (kdf=0 = HKDF-SHA256 is unimplemented)
                    ("sign", ctypes.c_int),    # 0 = Ed25519
                    ("kem",  ctypes.c_int),    # 3 = ML-KEM-768 (full)
                    ("name", ctypes.c_char_p), # optional label (NULL → "Custom")
                ]

            lib.nextssl_cleanup.argtypes = []
            lib.nextssl_cleanup.restype = None
            lib.nextssl_cleanup()
            lib.nextssl_init_custom.argtypes = [ctypes.POINTER(NextsslCustomProfile)]
            lib.nextssl_init_custom.restype = ctypes.c_int

            prof   = NextsslCustomProfile(hash=0, aead=1, kdf=1, sign=0, kem=3, name=None)
            ret_c  = lib.nextssl_init_custom(ctypes.byref(prof))
            level_c = lib.nextssl_security_level()
            if ret_c != 0 or level_c != b"custom":
                console.print_fail(f"nextssl_init_custom failed (ret={ret_c}, level={level_c})")
                failed += 1
            else:
                console.print_pass("nextssl_init_custom + security_level 'custom' OK")
            lib.nextssl_cleanup()
            lib.nextssl_init(0)  # restore MODERN for remaining tests
        except Exception as e:
            console.print_fail(f"nextssl_init_custom failed: {e}")
            failed += 1

        # ── Root / explicit-algorithm ──

        # root_sha256 KAT
        try:
            lib.nextssl_root_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_root_sha256.restype = ctypes.c_int
            out_r = ctypes.create_string_buffer(32)
            ret = lib.nextssl_root_sha256(b"abc", 3, out_r)
            if ret != 0 or out_r.raw.hex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
                console.print_fail(f"nextssl_root_sha256 KAT mismatch (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_root_sha256 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_sha256 failed: {e}")
            failed += 1

        # root_sha512 KAT
        try:
            lib.nextssl_root_sha512.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_root_sha512.restype = ctypes.c_int
            out_512 = ctypes.create_string_buffer(64)
            ret = lib.nextssl_root_sha512(b"abc", 3, out_512)
            sha512_abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            if ret != 0 or out_512.raw.hex() != sha512_abc:
                console.print_fail(f"nextssl_root_sha512 KAT mismatch (ret={ret})")
                failed += 1
            else:
                console.print_pass("nextssl_root_sha512 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_sha512 failed: {e}")
            failed += 1

        # root_blake3 KAT
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

        # root_sha1 (legacy/alive KAT: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d)
        try:
            lib.nextssl_root_sha1.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_root_sha1.restype = ctypes.c_int
            out_sha1 = ctypes.create_string_buffer(20)
            ret = lib.nextssl_root_sha1(b"abc", 3, out_sha1)
            sha1_abc = "a9993e364706816aba3e25717850c26c9cd0d89d"
            if ret != 0 or out_sha1.raw.hex() != sha1_abc:
                console.print_fail(f"nextssl_root_sha1 KAT mismatch (ret={ret}), got {out_sha1.raw.hex()}")
                failed += 1
            else:
                console.print_pass("nextssl_root_sha1 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_sha1 failed: {e}")
            failed += 1

        # root_md5 (legacy/alive KAT: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72)
        try:
            lib.nextssl_root_md5.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            lib.nextssl_root_md5.restype = ctypes.c_int
            out_md5 = ctypes.create_string_buffer(16)
            ret = lib.nextssl_root_md5(b"abc", 3, out_md5)
            md5_abc = "900150983cd24fb0d6963f7d28e17f72"
            if ret != 0 or out_md5.raw.hex() != md5_abc:
                console.print_fail(f"nextssl_root_md5 KAT mismatch (ret={ret}), got {out_md5.raw.hex()}")
                failed += 1
            else:
                console.print_pass("nextssl_root_md5 KAT OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_md5 failed: {e}")
            failed += 1

        # root_aes256gcm / root_chacha20 round-trips
        for algo_name, enc_fn, dec_fn in [
            ("AES-256-GCM",       "nextssl_root_aes256gcm_encrypt", "nextssl_root_aes256gcm_decrypt"),
            ("ChaCha20-Poly1305", "nextssl_root_chacha20_encrypt",  "nextssl_root_chacha20_decrypt"),
        ]:
            try:
                enc = getattr(lib, enc_fn)
                dec = getattr(lib, dec_fn)
                enc.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
                enc.restype = ctypes.c_int
                dec.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
                dec.restype = ctypes.c_int
                key   = bytes(range(32))
                nonce = bytes(range(12))
                pt    = b"root aead test"
                ct_x  = ctypes.create_string_buffer(len(pt) + 16)
                ret   = enc(key, nonce, pt, len(pt), ct_x)
                if ret != 0:
                    console.print_fail(f"{algo_name} encrypt failed (ret={ret})")
                    failed += 1
                else:
                    pt_x2 = ctypes.create_string_buffer(len(pt))
                    ret2  = dec(key, nonce, ct_x.raw, len(ct_x), pt_x2)
                    if ret2 != 0 or pt_x2.raw[:len(pt)] != pt:
                        console.print_fail(f"{algo_name} decrypt round-trip failed (ret={ret2})")
                        failed += 1
                    else:
                        console.print_pass(f"nextssl_root {algo_name} round-trip OK")
            except Exception as e:
                console.print_fail(f"nextssl_root {algo_name} round-trip failed: {e}")
                failed += 1

        # root_ed25519
        try:
            lib.nextssl_root_ed25519_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_ed25519_keygen.restype   = ctypes.c_int
            lib.nextssl_root_ed25519_sign.argtypes    = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_ed25519_sign.restype     = ctypes.c_int
            lib.nextssl_root_ed25519_verify.argtypes  = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_ed25519_verify.restype   = ctypes.c_int
            pk_e = ctypes.create_string_buffer(32)
            sk_e = ctypes.create_string_buffer(64)
            sig_e = ctypes.create_string_buffer(64)
            msg_e = b"root ed25519"
            lib.nextssl_root_ed25519_keygen(pk_e, sk_e)
            ret_s = lib.nextssl_root_ed25519_sign(sig_e, msg_e, len(msg_e), sk_e.raw)
            ret_v = lib.nextssl_root_ed25519_verify(sig_e.raw, msg_e, len(msg_e), pk_e.raw)
            if ret_s != 0 or ret_v != 1:
                console.print_fail(f"nextssl_root_ed25519 failed (s={ret_s}, v={ret_v})")
                failed += 1
            else:
                console.print_pass("nextssl_root_ed25519 sign/verify OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_ed25519 failed: {e}")
            failed += 1

        # root_mlkem768 (pk=1184 sk=2400 ct=1088 ss=32)
        try:
            lib.nextssl_root_mlkem768_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_mlkem768_keygen.restype   = ctypes.c_int
            lib.nextssl_root_mlkem768_encaps.argtypes  = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_mlkem768_encaps.restype   = ctypes.c_int
            lib.nextssl_root_mlkem768_decaps.argtypes  = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
            lib.nextssl_root_mlkem768_decaps.restype   = ctypes.c_int
            pk_k = ctypes.create_string_buffer(1184)
            sk_k = ctypes.create_string_buffer(2400)
            ct_k = ctypes.create_string_buffer(1088)
            ss_e = ctypes.create_string_buffer(32)
            ss_d = ctypes.create_string_buffer(32)
            lib.nextssl_root_mlkem768_keygen(pk_k, sk_k)
            ret_e = lib.nextssl_root_mlkem768_encaps(pk_k.raw, ct_k, ss_e)
            ret_d = lib.nextssl_root_mlkem768_decaps(ct_k.raw, sk_k.raw, ss_d)
            if ret_e != 0 or ret_d != 0 or ss_e.raw != ss_d.raw:
                console.print_fail(f"nextssl_root_mlkem768 KEM failed (e={ret_e}, d={ret_d}, match={ss_e.raw==ss_d.raw})")
                failed += 1
            else:
                console.print_pass("nextssl_root_mlkem768 KEM OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_mlkem768 failed: {e}")
            failed += 1

        # root_mldsa65 (pk=1952 sk=4032 sig_max=3309)
        try:
            lib.nextssl_root_mldsa65_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_mldsa65_keygen.restype   = ctypes.c_int
            lib.nextssl_root_mldsa65_sign.argtypes    = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa65_sign.restype     = ctypes.c_int
            lib.nextssl_root_mldsa65_verify.argtypes  = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa65_verify.restype   = ctypes.c_int
            pk_65 = ctypes.create_string_buffer(1952)
            sk_65 = ctypes.create_string_buffer(4032)
            sig_65 = ctypes.create_string_buffer(3309)
            sig_len_65 = ctypes.c_size_t(3309)
            msg_65 = b"root mldsa65"
            lib.nextssl_root_mldsa65_keygen(pk_65, sk_65)
            ret_s = lib.nextssl_root_mldsa65_sign(sig_65, ctypes.byref(sig_len_65), msg_65, len(msg_65), sk_65.raw)
            ret_v = lib.nextssl_root_mldsa65_verify(sig_65.raw, sig_len_65.value, msg_65, len(msg_65), pk_65.raw)
            if ret_s != 0 or ret_v != 1:
                console.print_fail(f"nextssl_root_mldsa65 failed (s={ret_s}, v={ret_v})")
                failed += 1
            else:
                console.print_pass("nextssl_root_mldsa65 sign/verify OK")
        except Exception as e:
            console.print_fail(f"nextssl_root_mldsa65 failed: {e}")
            failed += 1

        # root_mldsa87 (pk=2592 sk=4896 sig_max=4627)
        try:
            lib.nextssl_root_mldsa87_keygen.argtypes  = [ctypes.c_void_p, ctypes.c_void_p]
            lib.nextssl_root_mldsa87_keygen.restype   = ctypes.c_int
            lib.nextssl_root_mldsa87_sign.argtypes    = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa87_sign.restype     = ctypes.c_int
            lib.nextssl_root_mldsa87_verify.argtypes  = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.nextssl_root_mldsa87_verify.restype   = ctypes.c_int
            pk_87 = ctypes.create_string_buffer(2592)
            sk_87 = ctypes.create_string_buffer(4896)
            sig_87 = ctypes.create_string_buffer(4627)
            sig_len_87 = ctypes.c_size_t(4627)
            msg_87 = b"root mldsa87"
            lib.nextssl_root_mldsa87_keygen(pk_87, sk_87)
            ret_s = lib.nextssl_root_mldsa87_sign(sig_87, ctypes.byref(sig_len_87), msg_87, len(msg_87), sk_87.raw)
            ret_v = lib.nextssl_root_mldsa87_verify(sig_87.raw, sig_len_87.value, msg_87, len(msg_87), pk_87.raw)
            if ret_s != 0 or ret_v != 1:
                console.print_fail(f"nextssl_root_mldsa87 failed (s={ret_s}, v={ret_v})")
                failed += 1
            else:
                console.print_pass("nextssl_root_mldsa87 sign/verify OK")
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
            console.print_pass("Main unified DLL OK")
            return 0
        console.print_fail(f"Main unified DLL failed: {failed} checks")
        return 1
    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
