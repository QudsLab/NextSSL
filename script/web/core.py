"""
script/web/core.py — WASM functional tests for core.wasm (main tier).

Covers:
  AES-128-CBC (FIPS 197 KAT)
  AES-128-GCM (encrypt → ciphertext ≠ plaintext)
  ChaCha20-Poly1305 (encrypt → ciphertext ≠ plaintext)
  HMAC-SHA256 (RFC 4231 Test Case 1 KAT)
  Ed25519 (keygen + sign + verify round-trip)
"""
import os
import sys

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

# HMAC-SHA256: RFC 4231 Test Case 1
_HMAC_KEY      = bytes([0x0b] * 20)
_HMAC_DATA     = b"Hi There"
_HMAC_EXPECTED = bytes.fromhex(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

# Ed25519 deterministic seed (RFC 8037)
_ED25519_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44da4da053d0a5bea7f2311496cabab02c")
_ED25519_MSG  = b"hello"


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
