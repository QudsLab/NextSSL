# -*- coding: utf-8 -*-
"""
script/web/system_lite.py — WASM functional tests for main_lite.wasm (primary tier).

Covers ALL exported functions in _WASM_LITE_EXPORTS:
  High-level API (7):  nextssl_init, nextssl_init_custom, nextssl_cleanup,
                       nextssl_hash, nextssl_encrypt, nextssl_decrypt,
                       nextssl_security_level
  Root hash    (4):   nextssl_root_hash_sha256/sha512/blake3/argon2id
  Root ECC     (5):   nextssl_root_ecc_ed25519_keygen/sign/verify,
                      nextssl_root_ecc_x25519_keygen/exchange
  Root PQC KEM (3):   nextssl_root_pqc_kem_mlkem1024_keygen/encaps/decaps
  Root PQC Sign(3):   nextssl_root_pqc_sign_mldsa87_keygen/sign/verify
  Root PoW     (3):   nextssl_root_pow_server_challenge/client_solve/server_verify

ML-KEM-1024 sizes: pk=1568, sk=3168, ct=1568, ss=32
ML-DSA-87 sizes:   pk=2592, sk=4896, sig=4627 (max)
"""
import os
import sys
import struct as _struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module

# ── KAT vectors ───────────────────────────────────────────────────────────────
_SHA256_ABC = bytes.fromhex(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
_SHA512_ABC = bytes.fromhex(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

# ── Constants ─────────────────────────────────────────────────────────────────
NEXTSSL_PROFILE_MODERN = 0

_POW_CONFIG_SIZE    = 164
_POW_CHALLENGE_SIZE = 416
_POW_SOLUTION_SIZE  = 112


def _run_tests(m) -> _Tester:
    t = _Tester()

    # ══════════════════════════════════════════════════════════════════════════
    # A — High-level API
    # ══════════════════════════════════════════════════════════════════════════

    def _init():
        rc = m.call('nextssl_init', NEXTSSL_PROFILE_MODERN)
        return rc == 0
    t.run("nextssl_init(MODERN)", _init)

    # int nextssl_hash(data*, len, out[32]) → 0 ok  (SHA-256 in MODERN profile)
    def _hash():
        p_data = m.buf(b"abc")
        p_out  = m.zbuf(32)
        rc = m.call('nextssl_hash', p_data, 3, p_out)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA256_ABC
    t.run("nextssl_hash SHA-256 KAT", _hash)

    # int nextssl_encrypt/decrypt round-trip (AES-256-GCM by default)
    # overhead = 28 bytes (12-byte nonce + 16-byte tag)
    def _enc_dec():
        key = b'\xab' * 32
        pt  = b"test message!!\n"        # 16 bytes
        p_key   = m.buf(key)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(len(pt) + 28)
        p_ctlen = m.zbuf(4)
        rc1 = m.call('nextssl_encrypt', p_key, p_pt, len(pt), p_ct, p_ctlen)
        if rc1 != 0:
            for p in (p_key, p_pt, p_ct, p_ctlen): m.free(p)
            return False
        ct_len = _struct.unpack_from('<I', bytes(m.read(p_ctlen, 4)))[0]
        p_dt    = m.zbuf(len(pt))
        p_dtlen = m.zbuf(4)
        rc2 = m.call('nextssl_decrypt', p_key, p_ct, ct_len, p_dt, p_dtlen)
        recovered = bytes(m.read(p_dt, len(pt)))
        for p in (p_key, p_pt, p_ct, p_ctlen, p_dt, p_dtlen): m.free(p)
        return rc2 == 0 and recovered == pt
    t.run("nextssl_encrypt/decrypt round-trip", _enc_dec)

    # const char* nextssl_security_level(void) → non-NULL
    def _sec_level():
        ptr = m.call('nextssl_security_level')
        return ptr != 0
    t.run("nextssl_security_level returns non-NULL", _sec_level)

    # nextssl_init_custom — struct { i32 hash; i32 aead; i32 kdf; i32 sign;
    #                                i32 kem;  i32 pow;  i32 name; } = 28 B
    # Returns 0=ok, -2=already-initialized (both acceptable)
    def _init_custom():
        profile = _struct.pack('<iiiiiii', 0, 0, 1, 0, 0, 0, 0)  # name=NULL
        p_profile = m.buf(profile)
        rc = m.call('nextssl_init_custom', p_profile)
        m.free(p_profile)
        return rc == 0 or rc == -2
    t.run("nextssl_init_custom (0=ok, -2=already-init OK)", _init_custom)

    # ══════════════════════════════════════════════════════════════════════════
    # B — Root hash  (SHA-256, SHA-512, BLAKE3, Argon2id — no SHA3 in lite)
    # ══════════════════════════════════════════════════════════════════════════

    def _root_sha256():
        p_data = m.buf(b"abc"); p_out = m.zbuf(32)
        rc = m.call('nextssl_root_hash_sha256', p_data, 3, p_out)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA256_ABC
    t.run("nextssl_root_hash_sha256 KAT", _root_sha256)

    def _root_sha512():
        p_data = m.buf(b"abc"); p_out = m.zbuf(64)
        rc = m.call('nextssl_root_hash_sha512', p_data, 3, p_out)
        result = bytes(m.read(p_out, 64))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA512_ABC
    t.run("nextssl_root_hash_sha512 KAT", _root_sha512)

    # nextssl_root_hash_blake3(data*, len, out*, out_len) → 0
    def _root_blake3():
        p_data = m.buf(b"abc"); p_out = m.zbuf(32)
        rc = m.call('nextssl_root_hash_blake3', p_data, 3, p_out, 32)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result != b'\x00' * 32
    t.run("nextssl_root_hash_blake3 non-zero", _root_blake3)

    # nextssl_root_hash_argon2id(pw, pw_len, salt, salt_len,
    #                             t_cost, m_cost_kb, parallelism,
    #                             out*, out_len) → 0
    def _root_argon2id():
        p_pw   = m.buf(b"password"); p_salt = m.buf(b"saltsalt")
        p_out  = m.zbuf(32)
        rc = m.call('nextssl_root_hash_argon2id',
                    p_pw, 8, p_salt, 8, 1, 8, 1, p_out, 32)
        result = bytes(m.read(p_out, 32))
        m.free(p_pw); m.free(p_salt); m.free(p_out)
        return rc == 0 and result != b'\x00' * 32
    t.run("nextssl_root_hash_argon2id non-zero", _root_argon2id)

    # ══════════════════════════════════════════════════════════════════════════
    # C — Root ECC
    # ══════════════════════════════════════════════════════════════════════════

    # nextssl_root_ecc_ed25519_keygen(pk[32], sk[64]) → 0
    # nextssl_root_ecc_ed25519_sign(sig[64], msg*, msg_len, sk[64]) → 0
    # nextssl_root_ecc_ed25519_verify(sig[64], msg*, msg_len, pk[32]) → 1 valid
    def _root_ed25519():
        p_pk = m.zbuf(32); p_sk = m.zbuf(64)
        if m.call('nextssl_root_ecc_ed25519_keygen', p_pk, p_sk) != 0:
            m.free(p_pk); m.free(p_sk)
            return False
        if bytes(m.read(p_pk, 32)) == b'\x00' * 32:
            m.free(p_pk); m.free(p_sk)
            return False
        p_msg = m.buf(b"hello"); p_sig = m.zbuf(64)
        rc_sign = m.call('nextssl_root_ecc_ed25519_sign', p_sig, p_msg, 5, p_sk)
        ok_v = m.call('nextssl_root_ecc_ed25519_verify', p_sig, p_msg, 5, p_pk) == 1
        p_bad = m.buf(b"HELLO")
        ok_r = m.call('nextssl_root_ecc_ed25519_verify', p_sig, p_bad, 5, p_pk) == 0
        for p in (p_pk, p_sk, p_msg, p_sig, p_bad): m.free(p)
        return rc_sign == 0 and ok_v and ok_r
    t.run("nextssl_root_ecc_ed25519 keygen+sign+verify", _root_ed25519)

    # nextssl_root_ecc_x25519_keygen(pk[32], sk[32]) → 0
    # nextssl_root_ecc_x25519_exchange(my_sk[32], their_pk[32], ss[32]) → 0
    def _root_x25519():
        p_apk = m.zbuf(32); p_ask = m.zbuf(32)
        p_bpk = m.zbuf(32); p_bsk = m.zbuf(32)
        rc1 = m.call('nextssl_root_ecc_x25519_keygen', p_apk, p_ask)
        rc2 = m.call('nextssl_root_ecc_x25519_keygen', p_bpk, p_bsk)
        if rc1 != 0 or rc2 != 0:
            for p in (p_apk, p_ask, p_bpk, p_bsk): m.free(p)
            return False
        p_ss1 = m.zbuf(32); p_ss2 = m.zbuf(32)
        rc3 = m.call('nextssl_root_ecc_x25519_exchange', p_ask, p_bpk, p_ss1)
        rc4 = m.call('nextssl_root_ecc_x25519_exchange', p_bsk, p_apk, p_ss2)
        ss1 = bytes(m.read(p_ss1, 32)); ss2 = bytes(m.read(p_ss2, 32))
        for p in (p_apk, p_ask, p_bpk, p_bsk, p_ss1, p_ss2): m.free(p)
        return rc3 == 0 and rc4 == 0 and ss1 == ss2 and ss1 != b'\x00' * 32
    t.run("nextssl_root_ecc_x25519 ECDH round-trip", _root_x25519)

    # ══════════════════════════════════════════════════════════════════════════
    # D — Root PQC KEM (ML-KEM-1024 in lite: pk=1568, sk=3168, ct=1568, ss=32)
    # nextssl_root_pqc_kem_mlkem1024_keygen(pk*, sk*) → 0
    # nextssl_root_pqc_kem_mlkem1024_encaps(pk*, ct*, ss[32]) → 0
    # nextssl_root_pqc_kem_mlkem1024_decaps(sk*, ct*, ss[32]) → 0
    # ══════════════════════════════════════════════════════════════════════════
    def _root_mlkem1024():
        p_pk = m.zbuf(1568); p_sk = m.zbuf(3168)
        if m.call('nextssl_root_pqc_kem_mlkem1024_keygen', p_pk, p_sk) != 0:
            m.free(p_pk); m.free(p_sk)
            return False
        p_ct = m.zbuf(1568); p_ss1 = m.zbuf(32)
        if m.call('nextssl_root_pqc_kem_mlkem1024_encaps', p_pk, p_ct, p_ss1) != 0:
            for p in (p_pk, p_sk, p_ct, p_ss1): m.free(p)
            return False
        p_ss2 = m.zbuf(32)
        if m.call('nextssl_root_pqc_kem_mlkem1024_decaps', p_sk, p_ct, p_ss2) != 0:
            for p in (p_pk, p_sk, p_ct, p_ss1, p_ss2): m.free(p)
            return False
        ss1 = bytes(m.read(p_ss1, 32)); ss2 = bytes(m.read(p_ss2, 32))
        for p in (p_pk, p_sk, p_ct, p_ss1, p_ss2): m.free(p)
        return ss1 == ss2 and ss1 != b'\x00' * 32
    t.run("nextssl_root_pqc_kem_mlkem1024 KEM round-trip (ss match)", _root_mlkem1024)

    # ══════════════════════════════════════════════════════════════════════════
    # E — Root PQC Sign (ML-DSA-87 only in lite — no ML-DSA-65)
    # nextssl_root_pqc_sign_mldsa87_keygen(pk[2592], sk[4896]) → 0
    # nextssl_root_pqc_sign_mldsa87_sign(sk*, msg*, msg_len, sig*, sig_len*) → 0
    # nextssl_root_pqc_sign_mldsa87_verify(pk*, msg*, msg_len, sig*, sig_len) → 1
    # ══════════════════════════════════════════════════════════════════════════
    def _root_mldsa87():
        p_pk = m.zbuf(2592); p_sk = m.zbuf(4896)
        if m.call('nextssl_root_pqc_sign_mldsa87_keygen', p_pk, p_sk) != 0:
            m.free(p_pk); m.free(p_sk)
            return False
        p_sig = m.zbuf(4627); p_siglen = m.zbuf(4); p_msg = m.buf(b"hello")
        rc = m.call('nextssl_root_pqc_sign_mldsa87_sign',
                    p_sk, p_msg, 5, p_sig, p_siglen)
        siglen = _struct.unpack_from('<I', bytes(m.read(p_siglen, 4)))[0]
        ok = (rc == 0 and siglen > 0 and
              m.call('nextssl_root_pqc_sign_mldsa87_verify',
                     p_pk, p_msg, 5, p_sig, siglen) == 1)
        for p in (p_pk, p_sk, p_sig, p_siglen, p_msg): m.free(p)
        return ok
    t.run("nextssl_root_pqc_sign_mldsa87 keygen/sign/verify", _root_mldsa87)

    # ══════════════════════════════════════════════════════════════════════════
    # F — Root PoW  (SHA-256, d=4)
    # nextssl_root_pow_server_challenge(cfg*, algo_str*, ctx*, ctx_len,
    #                                   diff_bits, challenge*) → 0
    # nextssl_root_pow_client_solve(challenge*, solution*) → 0
    # nextssl_root_pow_server_verify(challenge*, solution*, valid*) → 0
    # ══════════════════════════════════════════════════════════════════════════
    def _root_pow():
        p_algo = m.buf(b"sha256\x00")
        cfg = bytearray(_POW_CONFIG_SIZE)
        _struct.pack_into('<I', cfg,   0, 4)              # difficulty_bits = 4
        _struct.pack_into('<Q', cfg,   8, 2**64 - 1)      # max_wu = UINT64_MAX
        _struct.pack_into('<Q', cfg,  16, 3600)           # challenge_ttl_seconds
        _struct.pack_into('<I', cfg,  24, p_algo)         # allowed_algos[0] ptr
        _struct.pack_into('<I', cfg, 152, 1)              # allowed_algos_count
        p_cfg = m.buf(bytes(cfg))

        p_challenge = m.zbuf(_POW_CHALLENGE_SIZE)
        rc1 = m.call('nextssl_root_pow_server_challenge',
                     p_cfg, p_algo, 0, 0, 4, p_challenge)
        if rc1 != 0:
            for p in (p_algo, p_cfg, p_challenge): m.free(p)
            return False

        p_solution = m.zbuf(_POW_SOLUTION_SIZE)
        rc2 = m.call('nextssl_root_pow_client_solve', p_challenge, p_solution)
        if rc2 != 0:
            for p in (p_algo, p_cfg, p_challenge, p_solution): m.free(p)
            return False

        p_valid = m.zbuf(4)
        rc3 = m.call('nextssl_root_pow_server_verify',
                     p_challenge, p_solution, p_valid)
        valid = bytes(m.read(p_valid, 1))[0]
        for p in (p_algo, p_cfg, p_challenge, p_solution, p_valid): m.free(p)
        return rc3 == 0 and valid == 1
    t.run("nextssl_root_pow challenge/solve/verify (d=4, sha256)", _root_pow)

    # ══════════════════════════════════════════════════════════════════════════
    # G — Cleanup
    # ══════════════════════════════════════════════════════════════════════════
    def _cleanup():
        m.call('nextssl_cleanup')   # void — must not crash
        return True
    t.run("nextssl_cleanup (no crash)", _cleanup)

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True) -> int:
    """Entry point called by runner.py via _MODULE_REGISTRY."""
    console.set_color(color)
    console.print_header("WASM lite tests (primary/main_lite.wasm)")

    mod, err = load_module('primary', 'main_lite')
    if mod is None:
        console.print_fail(f"Cannot load primary/main_lite.wasm: {err}")
        return 1

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(
        f"primary/main_lite.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
