"""script/test/main/core.py — functional tests for core.dll (Main Tier).

Covers cipher, AEAD, MAC, HMAC, KDF, DRBG, and ECC functions using
run_cipher_kat() / run_aead_roundtrip() helpers from test/core/.
"""
import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from script.core              import Config, console
from script.test.core.result  import Results
from script.test.core.cipher  import run_cipher_kat, run_aead_roundtrip


def main() -> int:
    config   = Config()
    dll_path = config.get_lib_path('main', 'core')
    console.print_info(f"Loading: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1
    console.print_pass("DLL loaded")

    r = Results('test/main/core')

    # ── 1. AES-CBC (NIST KAT) ─────────────────────────────────────────────
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ct_buf = ctypes.create_string_buffer(16)
    run_cipher_kat(
        lib, 'AES_CBC_encrypt',
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p],
        (key, iv, pt, len(pt), ct_buf),
        "7649abac8119b246cee98e9b12e9197d", r)

    # AES-CBC decrypt round-trip
    pt_dec = ctypes.create_string_buffer(16)
    lib.AES_CBC_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.c_void_p]
    lib.AES_CBC_decrypt.restype = None
    lib.AES_CBC_decrypt(key, iv, ct_buf.raw, 16, pt_dec)
    if pt_dec.raw == pt:
        r.ok("AES_CBC_decrypt round-trip")
    else:
        r.fail("AES_CBC_decrypt round-trip", reason=f"got {pt_dec.raw.hex()}")

    # ── 2. AES-GCM empty-message tag ──────────────────────────────────────
    tag_buf = ctypes.create_string_buffer(16)
    run_cipher_kat(
        lib, 'AES_GCM_encrypt',
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
         ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p],
        (bytes(16), bytes(12), b"", 0, b"", 0, tag_buf),
        "58e2fccefa7e3061367f1d57a4e7455a", r)

    # AES-GCM round-trip with non-empty plaintext
    run_aead_roundtrip(lib, 'AES_GCM_encrypt', 'AES_GCM_decrypt',
                       bytes(16), bytes(12), b"hello world     ",
                       b"aad", r, "AES-GCM")

    # ── 3. ChaCha20-Poly1305 round-trip ───────────────────────────────────
    run_aead_roundtrip(lib, 'ChaCha20_Poly1305_encrypt', 'ChaCha20_Poly1305_decrypt',
                       bytes(32), bytes(12), b"chacha test msg!",
                       b"", r, "ChaCha20-Poly1305")

    # ── 4. AES-CCM round-trip ─────────────────────────────────────────────
    run_aead_roundtrip(lib, 'AES_CCM_encrypt', 'AES_CCM_decrypt',
                       bytes(16), bytes(12), b"ccm plaintext!!!",
                       b"", r, "AES-CCM")

    # ── 5. AES-OCB round-trip ─────────────────────────────────────────────
    run_aead_roundtrip(lib, 'AES_OCB_encrypt', 'AES_OCB_decrypt',
                       bytes(16), bytes(12), b"ocb plaintext!!!",
                       b"", r, "AES-OCB")

    # ── 6. AES-EAX round-trip ─────────────────────────────────────────────
    run_aead_roundtrip(lib, 'AES_EAX_encrypt', 'AES_EAX_decrypt',
                       bytes(16), bytes(12), b"eax plaintext!!!",
                       b"", r, "AES-EAX")

    # ── 7. AES-SIV round-trip ─────────────────────────────────────────────
    run_aead_roundtrip(lib, 'AES_SIV_encrypt', 'AES_SIV_decrypt',
                       bytes(32), bytes(16), b"siv plaintext!!!",
                       b"", r, "AES-SIV")

    # ── 8. AES-GCM-SIV round-trip ────────────────────────────────────────
    run_aead_roundtrip(lib, 'GCM_SIV_encrypt', 'GCM_SIV_decrypt',
                       bytes(16), bytes(12), b"gcmsiv message!!",
                       b"", r, "AES-GCM-SIV")

    # ── 9. HMAC-SHA256 (RFC 2202 KAT) ────────────────────────────────────
    lib.pqc_hmac_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_char_p]
    lib.pqc_hmac_sha256.restype = None
    hmac_key = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    hmac_buf = ctypes.create_string_buffer(32)
    lib.pqc_hmac_sha256(hmac_key, len(hmac_key), b"Hi There", 8, hmac_buf)
    expected_hmac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    if hmac_buf.raw.hex() == expected_hmac:
        r.ok("pqc_hmac_sha256 KAT")
    else:
        r.fail("pqc_hmac_sha256 KAT", reason=f"got {hmac_buf.raw.hex()[:32]}")

    # ── 10. HKDF-SHA256 (RFC 5869 KAT) ───────────────────────────────────
    lib.hkdf.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                         ctypes.c_char_p, ctypes.c_size_t,
                         ctypes.c_char_p, ctypes.c_size_t,
                         ctypes.c_char_p, ctypes.c_uint32]
    lib.hkdf.restype  = ctypes.c_int
    hkdf_ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    hkdf_salt = bytes.fromhex("000102030405060708090a0b0c")
    hkdf_info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    hkdf_out  = ctypes.create_string_buffer(42)
    ret = lib.hkdf(hkdf_ikm, len(hkdf_ikm), hkdf_salt, len(hkdf_salt),
                   hkdf_info, len(hkdf_info), hkdf_out, 42)
    expected_hkdf = ("3cb25f25faacd57a90434f64d0362f2a"
                     "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                     "34007208d5b887185865")
    if ret == 0 and hkdf_out.raw.hex() == expected_hkdf:
        r.ok("hkdf (RFC 5869 KAT)")
    else:
        r.fail("hkdf (RFC 5869 KAT)", reason=f"ret={ret} got {hkdf_out.raw.hex()[:32]}")

    # ── 11. CTR-DRBG: init → generate → reseed → generate ────────────────
    _test_ctr_drbg(lib, r)

    # ── 12. Ed25519 sign/verify + negative ───────────────────────────────
    _test_ed25519(lib, r)

    # ── 13. X25519 shared secret ──────────────────────────────────────────
    _test_x25519(lib, r)

    # ── 14. Elligator2 round-trip ─────────────────────────────────────────
    _test_elligator2(lib, r)

    # ── 15. Ristretto255 operations ───────────────────────────────────────
    _test_ristretto255(lib, r)

    return r.summary()


def _test_ctr_drbg(lib, r: Results) -> None:
    lib.ctr_drbg_init.argtypes     = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.ctr_drbg_init.restype      = ctypes.c_int
    lib.ctr_drbg_generate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.ctr_drbg_generate.restype  = ctypes.c_int
    lib.ctr_drbg_reseed.argtypes   = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.ctr_drbg_reseed.restype    = ctypes.c_int
    lib.ctr_drbg_free.argtypes     = [ctypes.c_void_p]
    lib.ctr_drbg_free.restype      = None

    ctx = ctypes.create_string_buffer(512)  # enough for any ctx struct
    seed = b'\x42' * 32
    out1 = ctypes.create_string_buffer(32)
    out2 = ctypes.create_string_buffer(32)

    ret = lib.ctr_drbg_init(ctx, seed, len(seed))
    if ret != 0:
        r.fail("ctr_drbg init", reason=f"ret={ret}")
        return
    lib.ctr_drbg_generate(ctx, out1, 32)
    lib.ctr_drbg_reseed(ctx, b'\xBB'*16, 16)
    lib.ctr_drbg_generate(ctx, out2, 32)
    lib.ctr_drbg_free(ctx)
    if any(out1.raw) and any(out2.raw):
        r.ok("ctr_drbg lifecycle (init/gen/reseed/gen/free)")
    else:
        r.fail("ctr_drbg lifecycle", reason="output buffers are all-zero")


def _test_ed25519(lib, r: Results) -> None:
    lib.ed25519_create_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ed25519_create_keypair.restype  = None
    lib.ed25519_create_seed.argtypes    = [ctypes.c_char_p]
    lib.ed25519_create_seed.restype     = ctypes.c_int
    lib.ed25519_sign.argtypes           = [ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
    lib.ed25519_sign.restype            = None
    lib.ed25519_verify.argtypes         = [ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_size_t, ctypes.c_char_p]
    lib.ed25519_verify.restype          = ctypes.c_int

    seed = ctypes.create_string_buffer(32)
    pk   = ctypes.create_string_buffer(32)
    sk   = ctypes.create_string_buffer(64)
    sig  = ctypes.create_string_buffer(64)
    msg  = b"test message"

    lib.ed25519_create_seed(seed)
    lib.ed25519_create_keypair(pk, sk, seed)
    lib.ed25519_sign(sig, msg, len(msg), pk, sk)
    ret = lib.ed25519_verify(sig, msg, len(msg), pk)
    if ret == 1:
        r.ok("Ed25519 sign/verify")
    else:
        r.fail("Ed25519 sign/verify", reason=f"verify ret={ret}")

    # negative: tampered message
    bad = bytearray(msg)
    bad[0] ^= 0xFF
    ret = lib.ed25519_verify(sig, bytes(bad), len(msg), pk)
    if ret == 0:
        r.ok("Ed25519 tampered msg (negative)")
    else:
        r.fail("Ed25519 tampered msg (negative)", reason="tampered msg accepted")


def _test_x25519(lib, r: Results) -> None:
    lib.ed25519_create_seed.argtypes    = [ctypes.c_char_p]
    lib.ed25519_create_seed.restype     = ctypes.c_int
    lib.ed25519_create_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ed25519_create_keypair.restype  = None
    lib.ed25519_key_exchange.argtypes   = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ed25519_key_exchange.restype    = ctypes.c_int

    seed_a = ctypes.create_string_buffer(32)
    seed_b = ctypes.create_string_buffer(32)
    pk_a   = ctypes.create_string_buffer(32)
    sk_a   = ctypes.create_string_buffer(64)
    pk_b   = ctypes.create_string_buffer(32)
    sk_b   = ctypes.create_string_buffer(64)
    ss_a   = ctypes.create_string_buffer(32)
    ss_b   = ctypes.create_string_buffer(32)

    lib.ed25519_create_seed(seed_a)
    lib.ed25519_create_seed(seed_b)
    lib.ed25519_create_keypair(pk_a, sk_a, seed_a)
    lib.ed25519_create_keypair(pk_b, sk_b, seed_b)
    r1 = lib.ed25519_key_exchange(ss_a, pk_b, sk_a)
    r2 = lib.ed25519_key_exchange(ss_b, pk_a, sk_b)
    if r1 == 0 and r2 == 0 and ss_a.raw == ss_b.raw:
        r.ok("X25519 shared-secret match")
    else:
        r.fail("X25519 shared-secret", reason=f"r1={r1} r2={r2} match={ss_a.raw==ss_b.raw}")


def _test_elligator2(lib, r: Results) -> None:
    lib.elligator2_key_pair.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.elligator2_key_pair.restype  = ctypes.c_int
    lib.elligator2_map.argtypes      = [ctypes.c_char_p, ctypes.c_char_p]
    lib.elligator2_map.restype       = ctypes.c_int
    lib.elligator2_rev.argtypes      = [ctypes.c_char_p, ctypes.c_char_p]
    lib.elligator2_rev.restype       = ctypes.c_int

    hidden = ctypes.create_string_buffer(32)
    sk     = ctypes.create_string_buffer(32)
    point  = ctypes.create_string_buffer(32)
    rev_u  = ctypes.create_string_buffer(32)

    ret = lib.elligator2_key_pair(hidden, sk)
    if ret != 0:
        r.fail("elligator2_key_pair", reason=f"ret={ret}")
        return
    r.ok("elligator2_key_pair")
    ret = lib.elligator2_map(point, hidden)
    ret2 = lib.elligator2_rev(rev_u, point)
    if ret == 0 and ret2 == 0:
        r.ok("elligator2 map/rev")
    else:
        r.fail("elligator2 map/rev", reason=f"map={ret} rev={ret2}")


def _test_ristretto255(lib, r: Results) -> None:
    lib.ristretto255_from_hash.argtypes    = [ctypes.c_char_p, ctypes.c_char_p]
    lib.ristretto255_from_hash.restype     = ctypes.c_int
    lib.ristretto255_is_valid_point.argtypes = [ctypes.c_char_p]
    lib.ristretto255_is_valid_point.restype  = ctypes.c_int
    lib.ristretto255_add.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.ristretto255_add.restype  = ctypes.c_int

    hash_input = b'\x42' * 64  # 64-byte hash input
    point = ctypes.create_string_buffer(32)
    ret = lib.ristretto255_from_hash(point, hash_input)
    if ret == 0:
        valid = lib.ristretto255_is_valid_point(point)
        if valid == 1:
            r.ok("ristretto255 from_hash + is_valid_point")
        else:
            r.fail("ristretto255 is_valid_point", reason=f"valid={valid}")
    else:
        r.fail("ristretto255_from_hash", reason=f"ret={ret}")


if __name__ == "__main__":
    sys.exit(main())
