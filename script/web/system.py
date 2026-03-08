"""
script/web/system.py — WASM functional tests for main.wasm (primary tier).

Covers ALL 35 exported functions in _WASM_SYSTEM_EXPORTS:

  High-level API (8):
    nextssl_init, nextssl_init_custom, nextssl_cleanup,
    nextssl_hash, nextssl_sha256, nextssl_encrypt, nextssl_decrypt,
    nextssl_security_level

  Root hash layer (5):
    nextssl_root_hash_sha256, nextssl_root_hash_sha512,
    nextssl_root_hash_sha3_256, nextssl_root_hash_blake3,
    nextssl_root_hash_argon2id

  Root ECC (5):
    nextssl_root_ecc_ed25519_keygen/sign/verify,
    nextssl_root_ecc_x25519_keygen/exchange

  Root PQC KEM (3):  nextssl_root_pqc_kem_mlkem768_keygen/encaps/decaps
  Root PQC Sign (6): nextssl_root_pqc_sign_mldsa65_*/mldsa87_*

  Root PoW (3):
    nextssl_root_pow_server_challenge,
    nextssl_root_pow_server_verify, nextssl_root_pow_client_solve

  Root legacy alive (2):
    nextssl_root_legacy_alive_sha1, nextssl_root_legacy_alive_md5

  DHCM cost model (3):
    nextssl_dhcm_expected_trials, nextssl_dhcm_calculate,
    nextssl_dhcm_get_algorithm_info

  Compat exports (2):  AES_CBC_encrypt, pqc_mlkem512_keypair

Struct layouts (WASM32):

  DHCMParams:  uint32[5] at +0/+4/+8/+12/+16 (algorithm, model, zeros,
               input_size, output_size); pad to 64 bytes
  DHCMResult:  uint64 wu_per_eval@+0, double expected_trials@+8; 64 bytes
  POWConfig (164 bytes):  u32 difficulty_bits@0, u64 max_wu@8, u64 ttl@16,
               char* allowed_algos[0]@24, u32 count@152
  POWChallenge: 416 bytes (zeroed output buffer)
  POWSolution:  112 bytes (zeroed output buffer)
  nextssl_custom_profile_t: int[6] + char* = 28 bytes

  KC (nextssl_root_pqc_kem_mlkem768 sizes): pk=1184, sk=2400, ct=1088, ss=32
  ML-DSA-65 sizes: pk=1952, sk=4032, sig_max=3309
  ML-DSA-87 sizes: pk=2592, sk=4896, sig_max=4627

DHCM / init enums:
  DHCM_SHA256 = 0x0100
  DHCM_DIFFICULTY_TARGET_BASED = 1
  NEXTSSL_PROFILE_MODERN = 0
"""
import os
import sys
import struct as _struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module

# ── KAT vectors ───────────────────────────────────────────────────────────────
_SHA256_ABC  = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
_SHA512_ABC  = bytes.fromhex(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
_SHA3_256_ABC = bytes.fromhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
_SHA1_ABC    = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
_MD5_ABC     = bytes.fromhex("900150983cd24fb0d6963f7d28e17f72")
_AES_CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_AES_CBC_IV  = bytes(range(16))
_AES_CBC_PT  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
_AES_CBC_CT  = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

# ── Enum / constant values ────────────────────────────────────────────────────
DHCM_SHA256                  = 0x0100
DHCM_DIFFICULTY_TARGET_BASED = 1
NEXTSSL_PROFILE_MODERN       = 0
_POW_CONFIG_SIZE    = 164
_POW_CHALLENGE_SIZE = 416
_POW_SOLUTION_SIZE  = 112


def _run_tests(mod) -> _Tester:
    t = _Tester()
    m = mod

    # ══════════════════════════════════════════════════════════════════════════
    # A — High-level API
    # ══════════════════════════════════════════════════════════════════════════

    # ── nextssl_init ─────────────────────────────────────────────────────────
    def _init():
        rc = m.call('nextssl_init', NEXTSSL_PROFILE_MODERN)
        return rc == 0
    t.run("nextssl_init(MODERN)", _init)

    # ── nextssl_hash SHA-256 KAT ──────────────────────────────────────────────
    # int nextssl_hash(data*, len, out[32]) → 0 ok
    def _hash():
        p_data = m.buf(b"abc")
        p_out  = m.zbuf(32)
        rc = m.call('nextssl_hash', p_data, 3, p_out)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA256_ABC
    t.run("nextssl_hash SHA-256 KAT", _hash)

    # ── nextssl_sha256 (raw export) KAT ──────────────────────────────────────
    # int nextssl_sha256(data*, len, out[32]) → 0 ok
    def _sha256_raw():
        p_data = m.buf(b"abc")
        p_out  = m.zbuf(32)
        rc = m.call('nextssl_sha256', p_data, 3, p_out)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA256_ABC
    t.run("nextssl_sha256 KAT (raw export)", _sha256_raw)

    # ── nextssl_encrypt / nextssl_decrypt round-trip ──────────────────────────
    # int nextssl_encrypt(key[32], pt*, pt_len, ct*, ct_len*) → 0 ok
    # int nextssl_decrypt(key[32], ct*, ct_len, pt*, pt_len*) → 0 ok
    # AES-256-GCM overhead = 28 bytes (12-byte nonce + 16-byte tag)
    def _enc_dec():
        key = b'\xab' * 32
        pt  = b"test message!!\n"   # 16 bytes
        p_key   = m.buf(key)
        p_pt    = m.buf(pt)
        p_ct    = m.zbuf(len(pt) + 28)
        p_ctlen = m.zbuf(4)          # size_t* output
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

    # ── nextssl_security_level ────────────────────────────────────────────────
    # const char* nextssl_security_level(void) → non-NULL ptr
    def _sec_level():
        ptr = m.call('nextssl_security_level')
        return ptr != 0
    t.run("nextssl_security_level returns non-NULL", _sec_level)

    # ── nextssl_init_custom ───────────────────────────────────────────────────
    # struct { int hash; int aead; int kdf; int sign; int kem; int pow;
    #          const char *name; }  = 28 bytes (WASM32)
    # Returns 0=ok, -2=already-initialized (both acceptable)
    def _init_custom():
        # MODERN-equivalent: SHA-256/AES-256-GCM/Argon2id/Ed25519/X25519
        profile = _struct.pack('<iiiiiii', 0, 0, 1, 0, 0, 0, 0)  # name=NULL
        p_profile = m.buf(profile)
        rc = m.call('nextssl_init_custom', p_profile)
        m.free(p_profile)
        return rc == 0 or rc == -2    # -2 = already initialized
    t.run("nextssl_init_custom (0=ok, -2=already-init OK)", _init_custom)

    # ══════════════════════════════════════════════════════════════════════════
    # B — Root hash layer
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

    def _root_sha3_256():
        p_data = m.buf(b"abc"); p_out = m.zbuf(32)
        rc = m.call('nextssl_root_hash_sha3_256', p_data, 3, p_out)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA3_256_ABC
    t.run("nextssl_root_hash_sha3_256 KAT", _root_sha3_256)

    def _root_blake3():
        p_data = m.buf(b"abc"); p_out = m.zbuf(32)
        rc = m.call('nextssl_root_hash_blake3', p_data, 3, p_out, 32)
        result = bytes(m.read(p_out, 32))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result != b'\x00' * 32
    t.run("nextssl_root_hash_blake3 non-zero", _root_blake3)

    # nextssl_root_hash_argon2id(pw, pw_len, salt, salt_len,
    #                            t_cost, m_cost_kb, parallelism,
    #                            out*, out_len) → 0 ok
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
    # D — Root PQC KEM  (ML-KEM-768: pk=1184, sk=2400, ct=1088, ss=32)
    # nextssl_root_pqc_kem_mlkem768_keygen(pk*, sk*) → 0
    # nextssl_root_pqc_kem_mlkem768_encaps(pk*, ct*, ss[32]) → 0
    # nextssl_root_pqc_kem_mlkem768_decaps(ct*, sk*, ss[32]) → 0
    # ══════════════════════════════════════════════════════════════════════════
    def _root_mlkem768():
        p_pk = m.zbuf(1184); p_sk = m.zbuf(2400)
        if m.call('nextssl_root_pqc_kem_mlkem768_keygen', p_pk, p_sk) != 0:
            m.free(p_pk); m.free(p_sk)
            return False
        p_ct = m.zbuf(1088); p_ss1 = m.zbuf(32)
        if m.call('nextssl_root_pqc_kem_mlkem768_encaps', p_pk, p_ct, p_ss1) != 0:
            for p in (p_pk, p_sk, p_ct, p_ss1): m.free(p)
            return False
        p_ss2 = m.zbuf(32)
        if m.call('nextssl_root_pqc_kem_mlkem768_decaps', p_ct, p_sk, p_ss2) != 0:
            for p in (p_pk, p_sk, p_ct, p_ss1, p_ss2): m.free(p)
            return False
        ss1 = bytes(m.read(p_ss1, 32)); ss2 = bytes(m.read(p_ss2, 32))
        for p in (p_pk, p_sk, p_ct, p_ss1, p_ss2): m.free(p)
        return ss1 == ss2
    t.run("nextssl_root_pqc_kem_mlkem768 KEM round-trip", _root_mlkem768)

    # ══════════════════════════════════════════════════════════════════════════
    # E — Root PQC Sign
    # sign(sig*, sig_len*, msg*, msg_len, sk*) → 0 ok
    # verify(sig*, sig_len, msg*, msg_len, pk*) → 1 valid
    # ══════════════════════════════════════════════════════════════════════════
    def _sign_roundtrip(prefix, pk_sz, sk_sz, sig_max):
        p_pk = m.zbuf(pk_sz); p_sk = m.zbuf(sk_sz)
        if m.call(f'{prefix}_keygen', p_pk, p_sk) != 0:
            m.free(p_pk); m.free(p_sk)
            return False
        p_sig = m.zbuf(sig_max); p_siglen = m.zbuf(4); p_msg = m.buf(b"hello")
        rc = m.call(f'{prefix}_sign', p_sig, p_siglen, p_msg, 5, p_sk)
        siglen = _struct.unpack_from('<I', bytes(m.read(p_siglen, 4)))[0]
        ok = (rc == 0 and siglen > 0 and
              m.call(f'{prefix}_verify', p_sig, siglen, p_msg, 5, p_pk) == 1)
        for p in (p_pk, p_sk, p_sig, p_siglen, p_msg): m.free(p)
        return ok

    t.run("nextssl_root_pqc_sign_mldsa65 sign/verify",
          lambda: _sign_roundtrip('nextssl_root_pqc_sign_mldsa65', 1952, 4032, 3309))
    t.run("nextssl_root_pqc_sign_mldsa87 sign/verify",
          lambda: _sign_roundtrip('nextssl_root_pqc_sign_mldsa87', 2592, 4896, 4627))

    # ══════════════════════════════════════════════════════════════════════════
    # F — Root PoW  (SHA-256, d=4)
    # nextssl_root_pow_server_challenge(cfg*, algo_str*, ctx*, ctx_len,
    #                                   diff_bits, challenge*) → 0 ok
    # nextssl_root_pow_client_solve(challenge*, solution*) → 0 ok
    # nextssl_root_pow_server_verify(challenge*, solution*, valid*) → 0 ok
    # ══════════════════════════════════════════════════════════════════════════
    def _root_pow():
        p_algo = m.buf(b"sha256\x00")      # algo string in WASM memory

        cfg = bytearray(_POW_CONFIG_SIZE)
        _struct.pack_into('<I', cfg,   0, 4)            # difficulty_bits = 4
        _struct.pack_into('<Q', cfg,   8, 2**64 - 1)    # max_wu = UINT64_MAX
        _struct.pack_into('<Q', cfg,  16, 3600)         # challenge_ttl_seconds
        _struct.pack_into('<I', cfg,  24, p_algo)       # allowed_algos[0] ptr
        _struct.pack_into('<I', cfg, 152, 1)            # allowed_algos_count
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
    # G — Root legacy alive (SHA-1, MD5 KATs)
    # int nextssl_root_legacy_alive_{sha1|md5}(data*, len, out*) → 0 ok
    # ══════════════════════════════════════════════════════════════════════════
    def _root_sha1():
        p_data = m.buf(b"abc"); p_out = m.zbuf(20)
        rc = m.call('nextssl_root_legacy_alive_sha1', p_data, 3, p_out)
        result = bytes(m.read(p_out, 20))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _SHA1_ABC
    t.run("nextssl_root_legacy_alive_sha1 KAT", _root_sha1)

    def _root_md5():
        p_data = m.buf(b"abc"); p_out = m.zbuf(16)
        rc = m.call('nextssl_root_legacy_alive_md5', p_data, 3, p_out)
        result = bytes(m.read(p_out, 16))
        m.free(p_data); m.free(p_out)
        return rc == 0 and result == _MD5_ABC
    t.run("nextssl_root_legacy_alive_md5 KAT", _root_md5)

    # ══════════════════════════════════════════════════════════════════════════
    # H — DHCM cost model
    # ══════════════════════════════════════════════════════════════════════════

    # nextssl_dhcm_expected_trials(model, zeros) → double
    def _dhcm_expected():
        result = m.call('nextssl_dhcm_expected_trials',
                        DHCM_DIFFICULTY_TARGET_BASED, 8)
        return isinstance(result, float) and abs(result - 256.0) < 0.01
    t.run("DHCM expected_trials (8 bits → 256.0)", _dhcm_expected)

    # nextssl_dhcm_calculate(params*, result*) → 0 ok
    def _dhcm_calc():
        params_buf = bytearray(64)
        _struct.pack_into('<I', params_buf,  0, DHCM_SHA256)
        _struct.pack_into('<I', params_buf,  4, DHCM_DIFFICULTY_TARGET_BASED)
        _struct.pack_into('<I', params_buf,  8, 8)    # target_leading_zeros
        _struct.pack_into('<I', params_buf, 12, 64)   # input_size
        _struct.pack_into('<I', params_buf, 16, 32)   # output_size
        p_params = m.buf(bytes(params_buf))
        p_result = m.zbuf(64)
        rc = m.call('nextssl_dhcm_calculate', p_params, p_result)
        if rc != 0:
            m.free(p_params); m.free(p_result)
            return False
        result_bytes = bytes(m.read(p_result, 16))
        wu     = _struct.unpack_from('<Q', result_bytes, 0)[0]
        trials = _struct.unpack_from('<d', result_bytes, 8)[0]
        m.free(p_params); m.free(p_result)
        return wu > 0 and trials > 0.0
    t.run("DHCM calculate (wu>0 and trials>0)", _dhcm_calc)

    # nextssl_dhcm_get_algorithm_info(algo, name**, wu*, block_size*) → 0 ok
    def _dhcm_info():
        p_name    = m.zbuf(4)   # char**  → i32*  (receives a wasm ptr)
        p_base_wu = m.zbuf(8)   # uint64_t*
        p_bsize   = m.zbuf(4)   # size_t*
        rc = m.call('nextssl_dhcm_get_algorithm_info',
                    DHCM_SHA256, p_name, p_base_wu, p_bsize)
        if rc != 0:
            m.free(p_name); m.free(p_base_wu); m.free(p_bsize)
            return False
        name_ptr = _struct.unpack_from('<I', bytes(m.read(p_name, 4)))[0]
        base_wu  = _struct.unpack_from('<Q', bytes(m.read(p_base_wu, 8)))[0]
        m.free(p_name); m.free(p_base_wu); m.free(p_bsize)
        return name_ptr != 0 and base_wu > 0
    t.run("DHCM get_algorithm_info (name≠NULL, wu>0)", _dhcm_info)

    # ══════════════════════════════════════════════════════════════════════════
    # I — Compat exports
    # ══════════════════════════════════════════════════════════════════════════

    # AES_CBC_encrypt(key, iv, pt, pt_len, ct) → void  [FIPS 197 KAT]
    def _compat_aes_cbc():
        p_key = m.buf(_AES_CBC_KEY); p_iv = m.buf(_AES_CBC_IV)
        p_pt  = m.buf(_AES_CBC_PT);  p_ct = m.zbuf(16)
        m.call('AES_CBC_encrypt', p_key, p_iv, p_pt, 16, p_ct)
        result = bytes(m.read(p_ct, 16))
        for p in (p_key, p_iv, p_pt, p_ct): m.free(p)
        return result == _AES_CBC_CT
    t.run("AES_CBC_encrypt compat KAT (FIPS 197)", _compat_aes_cbc)

    # pqc_mlkem512_keypair(pk*, sk*) → 0  [pk=800, sk=1632]
    def _compat_mlkem512():
        p_pk = m.zbuf(800); p_sk = m.zbuf(1632)
        rc = m.call('pqc_mlkem512_keypair', p_pk, p_sk)
        pk = bytes(m.read(p_pk, 32))
        m.free(p_pk); m.free(p_sk)
        return rc == 0 and pk != b'\x00' * 32
    t.run("pqc_mlkem512_keypair compat (pk non-zero)", _compat_mlkem512)

    # ══════════════════════════════════════════════════════════════════════════
    # J — Cleanup
    # ══════════════════════════════════════════════════════════════════════════
    def _cleanup():
        m.call('nextssl_cleanup')   # void — must not crash
        return True
    t.run("nextssl_cleanup (no crash)", _cleanup)

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True):
    """Run all main.wasm (primary) functional tests — covers all exported symbols."""
    console.set_color(color)
    console.print_header("WASM system tests (primary/main.wasm)")

    mod, err = load_module('primary', 'main')
    if mod is None:
        console.print_fail(f"Cannot load primary/main.wasm: {err}")
        return 1

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(f"primary/main.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
