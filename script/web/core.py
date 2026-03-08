"""
script/web/core.py — WASM functional tests for core.wasm (main tier).

Covers:
  Cipher  : AES-CBC, AES-CFB, AES-OFB, AES-CTR, AES-XTS, AES-KEY-Wrap, AES-ECB
  AEAD    : AES-GCM, AES-CCM, AES-OCB, AES-EAX, AES-SIV, GCM-SIV,
            AES-Poly1305, ChaCha20-Poly1305
  MAC     : AES-CMAC, SipHash
  HMAC/KDF: HMAC-SHA256, HMAC-SHA3-256/512, HKDF, HKDF-SHA3-256/512,
            HKDF-Expand-Label, KDF-SHAKE256
  DRBG    : CTR-DRBG (AES-256)
  ECC     : Ed25519 (keygen/sign/verify/key-exchange),
            Elligator2 (map/key-pair), Ristretto255 (from-hash/add)
"""
import os
import sys
import struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module


# ─────────────────────────────────────────────────────────────────────────────
# KAT vectors
# ─────────────────────────────────────────────────────────────────────────────

# AES-128-CBC: FIPS 197 first vector
_AES_CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_AES_CBC_IV  = bytes([i for i in range(16)])
_AES_CBC_PT  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
_AES_CBC_CT  = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

# AES-128-ECB: FIPS 197 first vector (no IV)
_AES_ECB_KEY = _AES_CBC_KEY
_AES_ECB_PT  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
_AES_ECB_CT  = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")

# HMAC-SHA256: RFC 4231 Test Case 1
_HMAC_KEY      = bytes([0x0b] * 20)
_HMAC_DATA     = b"Hi There"
_HMAC_EXPECTED = bytes.fromhex(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

# Ed25519 deterministic seed (RFC 8037)
_ED25519_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4da4da053d0a5bea7f2311496cabab02")
_ED25519_MSG  = b"hello"

# Common test constants
_KEY16  = b'\x01' * 16   # AES-128 key
_KEY32  = b'\x01' * 32   # AES-256 / double key (two 128-bit keys)
_IV12   = b'\x02' * 12   # 12-byte nonce
_IV16   = b'\x02' * 16   # 16-byte IV / block_t
_PT16   = b"test plaintext!!"  # 16 bytes

# CTR_DRBG_CTX layout: Key[32] + V[16] + reseed_counter[8] = 56 bytes
_CTR_DRBG_CTX_SIZE = 56


# ─────────────────────────────────────────────────────────────────────────────

def _run_tests(mod) -> _Tester:
    t = _Tester()
    m = mod

    # ── AES-128-CBC KAT ───────────────────────────────────────────────────────
    # AES_CBC_encrypt(key, iv, plaintext, len, ciphertext)  → void
    def _aes_cbc():
        p_key = m.buf(_AES_CBC_KEY)
        p_iv  = m.buf(_AES_CBC_IV)
        p_pt  = m.buf(_AES_CBC_PT)
        p_ct  = m.zbuf(16)
        m.call('AES_CBC_encrypt', p_key, p_iv, p_pt, 16, p_ct)
        result = m.read(p_ct, 16)
        for p in (p_key, p_iv, p_pt, p_ct):
            m.free(p)
        return result == _AES_CBC_CT
    t.run("AES-128-CBC KAT (FIPS 197)", _aes_cbc)

    # ── AES-128-GCM — ciphertext ≠ plaintext, ≠ all-zero ────────────────────
    # AES_GCM_encrypt(key, nonce, aData, aDataLen, pt, ptLen, ct)  → void
    def _aes_gcm():
        key   = b'\x00' * 16
        nonce = b'\x00' * 12
        pt    = b"test message!!\n"
        p_key   = m.buf(key)
        p_nonce = m.buf(nonce)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(16)
        m.call('AES_GCM_encrypt', p_key, p_nonce, 0, 0, p_pt, 16, p_ct)
        ct = m.read(p_ct, 16)
        for p in (p_key, p_nonce, p_pt, p_ct):
            m.free(p)
        return ct != pt and ct != b'\x00' * 16
    t.run("AES-128-GCM encrypt (non-trivial output)", _aes_gcm)

    # ── ChaCha20-Poly1305 — ciphertext ≠ plaintext ───────────────────────────
    # ChaCha20_Poly1305_encrypt(key, nonce, aData, aDataLen, pt, ptLen, ct)  → void
    def _chacha20():
        key   = b'\x00' * 32
        nonce = b'\x00' * 12
        pt    = b"test message!!\n"
        p_key   = m.buf(key)
        p_nonce = m.buf(nonce)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(16)
        m.call('ChaCha20_Poly1305_encrypt', p_key, p_nonce, 0, 0, p_pt, 16, p_ct)
        ct = m.read(p_ct, 16)
        for p in (p_key, p_nonce, p_pt, p_ct):
            m.free(p)
        return ct != pt and ct != b'\x00' * 16
    t.run("ChaCha20-Poly1305 encrypt (non-trivial output)", _chacha20)

    # ── HMAC-SHA256 KAT (RFC 4231 TC1) ───────────────────────────────────────
    # pqc_hmac_sha256(key, key_len, data, data_len, out)  → void
    def _hmac():
        p_key  = m.buf(_HMAC_KEY)
        p_data = m.buf(_HMAC_DATA)
        p_out  = m.zbuf(32)
        m.call('pqc_hmac_sha256', p_key, len(_HMAC_KEY),
               p_data, len(_HMAC_DATA), p_out)
        result = m.read(p_out, 32)
        for p in (p_key, p_data, p_out):
            m.free(p)
        return result == _HMAC_EXPECTED
    t.run("HMAC-SHA256 KAT (RFC 4231 TC1)", _hmac)

    # ── Ed25519 sign + verify round-trip ────────────────────────────────────
    # ed25519_create_keypair(pk, sk, seed)  → void
    # ed25519_sign(sig, msg, mlen, pk, sk)  → void
    # ed25519_verify(sig, msg, mlen, pk)    → int (1 = valid)
    def _ed25519():
        p_seed = m.buf(_ED25519_SEED)
        p_pk   = m.zbuf(32)
        p_sk   = m.zbuf(64)
        m.call('ed25519_create_keypair', p_pk, p_sk, p_seed)

        # pk must not be all-zero
        pk = m.read(p_pk, 32)
        if pk == b'\x00' * 32:
            return False

        p_msg = m.buf(_ED25519_MSG)
        p_sig = m.zbuf(64)
        m.call('ed25519_sign', p_sig, p_msg, len(_ED25519_MSG), p_pk, p_sk)

        # Valid verify must return 1
        ok_valid = m.call('ed25519_verify', p_sig, p_msg,
                          len(_ED25519_MSG), p_pk) == 1

        # Tampered message must NOT verify
        p_bad = m.buf(b"HELLO")
        ok_reject = m.call('ed25519_verify', p_sig, p_bad, 5, p_pk) == 0

        for p in (p_seed, p_pk, p_sk, p_msg, p_sig, p_bad):
            m.free(p)
        return ok_valid and ok_reject

    t.run("Ed25519 keygen + sign + verify round-trip", _ed25519)

    # ── AES-CBC decrypt round-trip ────────────────────────────────────────────
    def _aes_cbc_rt():
        p_key = m.buf(_AES_CBC_KEY)
        p_iv  = m.buf(_AES_CBC_IV)
        p_ct  = m.buf(_AES_CBC_CT)
        p_pt2 = m.zbuf(16)
        ret = m.call('AES_CBC_decrypt', p_key, p_iv, p_ct, 16, p_pt2)
        result = m.read(p_pt2, 16)
        for p in (p_key, p_iv, p_ct, p_pt2):
            m.free(p)
        return result == _AES_CBC_PT
    t.run("AES-128-CBC decrypt round-trip", _aes_cbc_rt)

    # ── AES-ECB (legacy/alive) KAT + round-trip ───────────────────────────────
    def _aes_ecb():
        p_key = m.buf(_AES_ECB_KEY)
        p_pt  = m.buf(_AES_ECB_PT)
        p_ct  = m.zbuf(16)
        m.call('AES_ECB_encrypt', p_key, p_pt, 16, p_ct)
        ct = m.read(p_ct, 16)
        if ct != _AES_ECB_CT:
            return False
        p_pt2 = m.zbuf(16)
        m.call('AES_ECB_decrypt', p_key, p_ct, 16, p_pt2)
        pt2 = m.read(p_pt2, 16)
        for p in (p_key, p_pt, p_ct, p_pt2):
            m.free(p)
        return pt2 == _AES_ECB_PT
    t.run("AES-ECB KAT (FIPS 197) + decrypt round-trip", _aes_ecb)

    # ── AES cipher round-trips (CFB / OFB / CTR) ─────────────────────────────
    def _sym_roundtrip(enc_fn, dec_fn, key, iv, pt):
        """Generic encrypt→decrypt round-trip for stream-like AES modes."""
        p_key = m.buf(key)
        p_iv  = m.buf(iv)
        p_pt  = m.buf(pt)
        p_ct  = m.zbuf(len(pt))
        m.call(enc_fn, p_key, p_iv, p_pt, len(pt), p_ct)
        ct = m.read(p_ct, len(pt))
        if ct == pt:
            for p in (p_key, p_iv, p_pt, p_ct): m.free(p)
            return False  # no-op encrypt is wrong
        p_pt2 = m.zbuf(len(pt))
        m.call(dec_fn, p_key, p_iv, p_ct, len(pt), p_pt2)
        result = m.read(p_pt2, len(pt))
        for p in (p_key, p_iv, p_pt, p_ct, p_pt2):
            m.free(p)
        return result == pt

    t.run("AES-CFB round-trip",
          lambda: _sym_roundtrip('AES_CFB_encrypt', 'AES_CFB_decrypt',
                                 _KEY16, _IV16, _PT16))
    t.run("AES-OFB round-trip",
          lambda: _sym_roundtrip('AES_OFB_encrypt', 'AES_OFB_decrypt',
                                 _KEY16, _IV16, _PT16))
    t.run("AES-CTR round-trip",
          lambda: _sym_roundtrip('AES_CTR_encrypt', 'AES_CTR_decrypt',
                                 _KEY16, _IV12, _PT16))

    # ── AES-XTS round-trip (needs two 128-bit keys = 32 bytes) ───────────────
    def _aes_xts():
        tweak = b'\x00' * 16  # sector number as block_t
        return _sym_roundtrip('AES_XTS_encrypt', 'AES_XTS_decrypt',
                              _KEY32, tweak, _PT16)
    t.run("AES-XTS round-trip", _aes_xts)

    # ── AES Key Wrap / Unwrap (RFC 3394) ─────────────────────────────────────
    def _aes_kw():
        # secret must be multiple of 8 bytes; wrapped = secretLen + 8
        secret = b'\xAB' * 16
        p_kek  = m.buf(_KEY16)
        p_sec  = m.buf(secret)
        p_wrap = m.zbuf(24)   # 16 + 8
        m.call('AES_KEY_wrap', p_kek, p_sec, 16, p_wrap)
        p_sec2 = m.zbuf(16)
        ret = m.call('AES_KEY_unwrap', p_kek, p_wrap, 24, p_sec2)
        result = m.read(p_sec2, 16)
        for p in (p_kek, p_sec, p_wrap, p_sec2):
            m.free(p)
        return result == secret
    t.run("AES-KEY-Wrap / Unwrap round-trip", _aes_kw)

    # ── AEAD round-trips ─────────────────────────────────────────────────────
    def _aead_roundtrip(enc_fn, dec_fn, key, nonce, ptlen, tag_len=16):
        """Encrypt then decrypt for AEAD modes that append a tag."""
        pt = _PT16[:ptlen]
        p_key   = m.buf(key)
        p_nonce = m.buf(nonce)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(ptlen + tag_len)  # ciphertext + authentication tag
        m.call(enc_fn, p_key, p_nonce, 0, 0, p_pt, ptlen, p_ct)
        p_pt2 = m.zbuf(ptlen)
        ret = m.call(dec_fn, p_key, p_nonce, 0, 0, p_ct, ptlen + tag_len, p_pt2)
        result = m.read(p_pt2, ptlen)
        for p in (p_key, p_nonce, p_pt, p_ct, p_pt2):
            m.free(p)
        return result == pt

    t.run("AES-GCM encrypt → decrypt round-trip",
          lambda: _aead_roundtrip('AES_GCM_encrypt', 'AES_GCM_decrypt',
                                  _KEY16, _IV12, 16))
    t.run("AES-OCB encrypt → decrypt round-trip",
          lambda: _aead_roundtrip('AES_OCB_encrypt', 'AES_OCB_decrypt',
                                  _KEY16, _IV12, 16))
    t.run("AES-EAX encrypt → decrypt round-trip",
          lambda: _aead_roundtrip('AES_EAX_encrypt', 'AES_EAX_decrypt',
                                  _KEY16, _IV12, 16))
    t.run("GCM-SIV encrypt → decrypt round-trip",
          lambda: _aead_roundtrip('GCM_SIV_encrypt', 'GCM_SIV_decrypt',
                                  _KEY16, _IV12, 16))

    # AES-CCM: typically nonce=11 bytes, ctLen = ptLen + tag_len
    def _aes_ccm():
        nonce = b'\x03' * 11   # CCM typically uses 7–13 byte nonce
        pt    = _PT16
        p_key   = m.buf(_KEY16)
        p_nonce = m.buf(nonce)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(32)   # ptLen + tag_len
        m.call('AES_CCM_encrypt', p_key, p_nonce, 0, 0, p_pt, 16, p_ct)
        p_pt2 = m.zbuf(16)
        ret = m.call('AES_CCM_decrypt', p_key, p_nonce, 0, 0, p_ct, 32, p_pt2)
        result = m.read(p_pt2, 16)
        for p in (p_key, p_nonce, p_pt, p_ct, p_pt2):
            m.free(p)
        return result == pt
    t.run("AES-CCM encrypt → decrypt round-trip", _aes_ccm)

    # AES-SIV: no nonce; IV is an output of encrypt and input to decrypt
    def _aes_siv():
        # AES-SIV needs two AES keys (32 bytes total for AES-128-SIV)
        keys   = _KEY32
        pt     = _PT16
        p_keys = m.buf(keys)
        p_pt   = m.buf(pt)
        p_iv   = m.zbuf(16)    # synthetic IV output (block_t)
        p_ct   = m.zbuf(16)    # ciphertext (same length as plaintext)
        m.call('AES_SIV_encrypt', p_keys, 0, 0, p_pt, 16, p_iv, p_ct)
        p_pt2 = m.zbuf(16)
        ret = m.call('AES_SIV_decrypt', p_keys, p_iv, 0, 0, p_ct, 16, p_pt2)
        result = m.read(p_pt2, 16)
        for p in (p_keys, p_pt, p_iv, p_ct, p_pt2):
            m.free(p)
        return result == pt
    t.run("AES-SIV encrypt → decrypt round-trip", _aes_siv)

    # AES-Poly1305: two-key MAC (32 bytes), yields 16-byte tag
    def _aes_poly1305():
        p_keys = m.buf(_KEY32)
        p_iv   = m.buf(_IV16)
        p_data = m.buf(_PT16)
        p_mac  = m.zbuf(16)
        m.call('AES_Poly1305', p_keys, p_iv, p_data, 16, p_mac)
        mac = m.read(p_mac, 16)
        for p in (p_keys, p_iv, p_data, p_mac):
            m.free(p)
        return mac != b'\x00' * 16
    t.run("AES-Poly1305 non-zero MAC", _aes_poly1305)

    # ChaCha20-Poly1305 decrypt round-trip
    def _chacha_rt():
        key   = b'\x00' * 32
        nonce = b'\x00' * 12
        pt    = b"test message!!\n"
        p_key   = m.buf(key)
        p_nonce = m.buf(nonce)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(32)   # 16 CT + 16 tag
        m.call('ChaCha20_Poly1305_encrypt', p_key, p_nonce, 0, 0, p_pt, 16, p_ct)
        p_pt2 = m.zbuf(16)
        m.call('ChaCha20_Poly1305_decrypt', p_key, p_nonce, 0, 0, p_ct, 32, p_pt2)
        result = m.read(p_pt2, 16)
        for p in (p_key, p_nonce, p_pt, p_ct, p_pt2):
            m.free(p)
        return result == pt
    t.run("ChaCha20-Poly1305 encrypt → decrypt round-trip", _chacha_rt)

    # ── MAC: AES-CMAC, SipHash ────────────────────────────────────────────────
    def _aes_cmac():
        # AES_CMAC(key, data, dataSize, mac[16])
        p_key  = m.buf(_KEY16)
        p_data = m.buf(_PT16)
        p_mac  = m.zbuf(16)
        m.call('AES_CMAC', p_key, p_data, 16, p_mac)
        mac = m.read(p_mac, 16)
        for p in (p_key, p_data, p_mac):
            m.free(p)
        return mac != b'\x00' * 16
    t.run("AES-CMAC non-zero output", _aes_cmac)

    def _siphash():
        # siphash(in, inlen, key[16], out, outlen) → int
        p_in  = m.buf(_PT16)
        p_key = m.buf(_KEY16)
        p_out = m.zbuf(8)
        m.call('siphash', p_in, 16, p_key, p_out, 8)
        mac = m.read(p_out, 8)
        for p in (p_in, p_key, p_out):
            m.free(p)
        return mac != b'\x00' * 8
    t.run("SipHash non-zero output", _siphash)

    # ── HMAC: SHA3-256, SHA3-512 ─────────────────────────────────────────────
    def _hmac_nz(fn, out_len):
        p_key  = m.buf(_HMAC_KEY)
        p_data = m.buf(_HMAC_DATA)
        p_out  = m.zbuf(out_len)
        m.call(fn, p_key, len(_HMAC_KEY), p_data, len(_HMAC_DATA), p_out)
        result = m.read(p_out, out_len)
        for p in (p_key, p_data, p_out):
            m.free(p)
        return result != b'\x00' * out_len
    t.run("HMAC-SHA3-256 non-zero", lambda: _hmac_nz('hmac_sha3_256', 32))
    t.run("HMAC-SHA3-512 non-zero", lambda: _hmac_nz('hmac_sha3_512', 64))

    # ── KDF: HKDF variants ───────────────────────────────────────────────────
    def _hkdf(fn, arg_count, out_len=32):
        """
        Full HKDF: hkdf(salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len)
        All-zero inputs → non-zero output (proves function ran).
        """
        ikm  = b'\x0b' * 22
        salt = b'\x00' * 13
        info = b'\xf0' * 10
        p_ikm  = m.buf(ikm)
        p_salt = m.buf(salt)
        p_info = m.buf(info)
        p_out  = m.zbuf(out_len)
        if arg_count == 8:
            m.call(fn, p_salt, len(salt), p_ikm, len(ikm),
                   p_info, len(info), p_out, out_len)
        elif arg_count == 5:
            # extract(salt, salt_len, ikm, ikm_len, prk)
            m.call(fn, p_salt, len(salt), p_ikm, len(ikm), p_out)
        elif arg_count == 6:
            # expand(prk, prk_len, info, info_len, okm, okm_len)
            m.call(fn, p_salt, 13, p_info, len(info), p_out, out_len)
        result = m.read(p_out, out_len)
        for p in (p_ikm, p_salt, p_info, p_out):
            m.free(p)
        return result != b'\x00' * out_len

    t.run("HKDF-SHA256 non-zero",         lambda: _hkdf('hkdf',         8))
    t.run("HKDF-SHA256 extract non-zero", lambda: _hkdf('hkdf_extract', 5, 32))
    t.run("HKDF-SHA256 expand non-zero",  lambda: _hkdf('hkdf_expand',  6))
    t.run("HKDF-SHA3-256 non-zero",       lambda: _hkdf('hkdf_sha3_256', 8))
    t.run("HKDF-SHA3-512 non-zero",       lambda: _hkdf('hkdf_sha3_512', 8, 64))

    def _hkdf_expand_label():
        # hkdf_expand_label(secret, secret_len, label, context, context_len, okm, okm_len)
        secret  = b'\xAA' * 32
        label   = b"tls13 key\x00"  # NUL-terminated C string
        context = b''
        p_sec   = m.buf(secret)
        p_label = m.buf(label)
        p_ctx   = m.buf(b'\x00')  # minimal non-null pointer
        p_out   = m.zbuf(32)
        m.call('hkdf_expand_label', p_sec, 32, p_label, p_ctx, 0, p_out, 32)
        result = m.read(p_out, 32)
        for p in (p_sec, p_label, p_ctx, p_out):
            m.free(p)
        return result != b'\x00' * 32
    t.run("HKDF-Expand-Label non-zero", _hkdf_expand_label)

    def _kdf_shake256():
        # kdf_shake256(ikm, ikm_len, info, info_len, okm, okm_len) → void
        ikm  = b'\x42' * 32
        info = b'\x1F' * 16
        p_ikm  = m.buf(ikm)
        p_info = m.buf(info)
        p_out  = m.zbuf(32)
        m.call('kdf_shake256', p_ikm, 32, p_info, 16, p_out, 32)
        result = m.read(p_out, 32)
        for p in (p_ikm, p_info, p_out):
            m.free(p)
        return result != b'\x00' * 32
    t.run("KDF-SHAKE256 non-zero", _kdf_shake256)

    # ── DRBG: CTR-DRBG (AES-256) ─────────────────────────────────────────────
    def _ctr_drbg():
        # CTR_DRBG_CTX: Key[32] + V[16] + counter[8] = 56 bytes
        entropy = b'\xDE' * 48   # 384-bit entropy
        p_ctx   = m.zbuf(_CTR_DRBG_CTX_SIZE)
        p_ent   = m.buf(entropy)
        p_out   = m.zbuf(32)
        m.call('ctr_drbg_init', p_ctx, p_ent, 48, 0, 0)
        m.call('ctr_drbg_generate', p_ctx, p_out, 32, 0, 0)
        result = m.read(p_out, 32)
        m.call('ctr_drbg_free', p_ctx)
        for p in (p_ctx, p_ent, p_out):
            m.free(p)
        return result != b'\x00' * 32
    t.run("CTR-DRBG init + generate non-zero", _ctr_drbg)

    # ── Ed25519 extras: key_exchange (X25519 DH) ─────────────────────────────
    def _ed25519_kex():
        # Each side: create_keypair from fixed seed → exchange
        seed_a = b'\x01' * 32
        seed_b = b'\x02' * 32
        p_seed_a = m.buf(seed_a); p_pk_a = m.zbuf(32); p_sk_a = m.zbuf(64)
        p_seed_b = m.buf(seed_b); p_pk_b = m.zbuf(32); p_sk_b = m.zbuf(64)
        m.call('ed25519_create_keypair', p_pk_a, p_sk_a, p_seed_a)
        m.call('ed25519_create_keypair', p_pk_b, p_sk_b, p_seed_b)
        p_shared_a = m.zbuf(32)
        p_shared_b = m.zbuf(32)
        m.call('ed25519_key_exchange', p_shared_a, p_pk_b, p_sk_a)
        m.call('ed25519_key_exchange', p_shared_b, p_pk_a, p_sk_b)
        sa = m.read(p_shared_a, 32)
        sb = m.read(p_shared_b, 32)
        for p in (p_seed_a, p_pk_a, p_sk_a, p_seed_b, p_pk_b, p_sk_b,
                  p_shared_a, p_shared_b):
            m.free(p)
        return sa == sb and sa != b'\x00' * 32
    t.run("Ed25519 key-exchange (X25519 DH) round-trip", _ed25519_kex)

    # ── Elligator2: map (deterministic, non-zero) ──────────────────────────────
    def _elligator2():
        # elligator2_map(curve[32], hidden[32]) → void
        hidden = b'\x5A' * 32
        p_hidden = m.buf(hidden)
        p_curve  = m.zbuf(32)
        m.call('elligator2_map', p_curve, p_hidden)
        result = m.read(p_curve, 32)
        # determinism: same hidden → same curve point
        p_h2 = m.buf(hidden)
        p_c2 = m.zbuf(32)
        m.call('elligator2_map', p_c2, p_h2)
        result2 = m.read(p_c2, 32)
        for p in (p_hidden, p_curve, p_h2, p_c2):
            m.free(p)
        return result != b'\x00' * 32 and result == result2
    t.run("Elligator2 map determinism + non-zero", _elligator2)

    # ── Ristretto255: from_hash + add ─────────────────────────────────────────
    def _ristretto255():
        # ristretto255_from_hash(p[32], r[64]) — r must be 64 bytes
        r = b'\xAB' * 64
        p_r = m.buf(r)
        p_p = m.zbuf(32)
        ret = m.call('ristretto255_from_hash', p_p, p_r)
        point = m.read(p_p, 32)
        # Add point to itself: result must differ from all-zero
        p_sum = m.zbuf(32)
        m.call('ristretto255_add', p_sum, p_p, p_p)
        p_sum_val = m.read(p_sum, 32)
        for p in (p_r, p_p, p_sum):
            m.free(p)
        return (ret == 0 and point != b'\x00' * 32
                and p_sum_val != b'\x00' * 32)
    t.run("Ristretto255 from_hash + add non-zero", _ristretto255)

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True):
    """Run all core.wasm functional tests.  Returns 0 on pass, 1 on fail."""
    console.set_color(color)
    console.print_header("WASM core tests")

    mod, err = load_module('main', 'core')
    if mod is None:
        console.print_fail(f"Cannot load core.wasm: {err}")
        return 1

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(f"core.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
