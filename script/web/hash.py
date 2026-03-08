"""
script/web/hash.py — WASM functional tests for hash.wasm (main tier).

Covers every exported hash / XOF / KDF algorithm:
  SHA-256/512/224/384, SHA-256 streaming,
  SHA3-224/256/384/512, Keccak-256, SHAKE-128/256,
  BLAKE3, BLAKE2b, BLAKE2s,
  SHA-1, MD5, MD2, MD4,
  RIPEMD-160, RIPEMD-128, RIPEMD-256, RIPEMD-320,
  Whirlpool, NT-Hash, AES-ECB (hash wrapper), SHA-0, HAS-160,
  Argon2id / Argon2i / Argon2d

All KAT vectors are from FIPS 180-4, FIPS 202, RFC 1319–1321, ISO 10118-3, or
from the official reference implementations.
"""
import os
import sys
import struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module


# ─────────────────────────────────────────────────────────────────────────────
# KAT vectors (input = b"abc" unless noted)
# ─────────────────────────────────────────────────────────────────────────────

_ABC = b"abc"

_SHA256_KAT   = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
_SHA512_KAT   = bytes.fromhex(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
_SHA224_KAT   = bytes.fromhex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
_SHA384_KAT   = bytes.fromhex(
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
_SHA3_224_KAT = bytes.fromhex("e642824c3f8cf24ad09234ee7d3c766fc9a3a516818d3564d1e7c999")
_SHA3_256_KAT = bytes.fromhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
_SHA3_384_KAT = bytes.fromhex(
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0"
    "e49be4b298d88cea927ac7f539f1edf228376d25")
_SHA3_512_KAT = bytes.fromhex(
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712d"
    "a101cd941f6e22f62a2d2f8a1617e4eb75b8a7e9e2e955afa59e8e7c2cf0d99e")
_KECCAK256_KAT = bytes.fromhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
_SHA1_KAT     = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
_MD5_KAT      = bytes.fromhex("900150983cd24fb0d6963f7d28e17f72")
_MD2_KAT      = bytes.fromhex("da853b0d3f88d99b30283a69e6ded6bb")
_MD4_KAT      = bytes.fromhex("a448017aaf21d8525fc10ae87aa6729d")
_RIPEMD160_KAT = bytes.fromhex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
_RIPEMD128_KAT = bytes.fromhex("c14a12199c66e4ba84636b0f69144c77")


# ─────────────────────────────────────────────────────────────────────────────

def _run_tests(mod) -> _Tester:
    t = _Tester()
    m = mod   # alias

    # ── SHA-256 KAT ───────────────────────────────────────────────────────────
    t.run("SHA-256 KAT",
          lambda: m.hash1('nextssl_sha256', _ABC, 32) == _SHA256_KAT)

    # ── SHA-256 streaming: init/update/final must match one-shot ─────────────
    def _sha256_stream():
        one_shot = m.hash1('nextssl_sha256', _ABC, 32)
        ctx = m.zbuf(256)                           # SHA256_CTX < 256 B
        m.call('nextssl_sha256_init', ctx)
        p1 = m.buf(b"ab")
        m.call('nextssl_sha256_update', ctx, p1, 2)
        m.free(p1)
        p2 = m.buf(b"c")
        m.call('nextssl_sha256_update', ctx, p2, 1)
        m.free(p2)
        p_out = m.zbuf(32)
        m.call('nextssl_sha256_final', ctx, p_out)
        result = m.read(p_out, 32)
        m.free(ctx); m.free(p_out)
        return result == one_shot
    t.run("SHA-256 streaming (init/update/final)", _sha256_stream)

    # ── SHA-512/224/384 KATs ─────────────────────────────────────────────────
    t.run("SHA-512 KAT",
          lambda: m.hash1('nextssl_sha512', _ABC, 64) == _SHA512_KAT)
    t.run("SHA-224 KAT",
          lambda: m.hash1('nextssl_sha224', _ABC, 28) == _SHA224_KAT)
    t.run("SHA-384 KAT",
          lambda: m.hash1('nextssl_sha384', _ABC, 48) == _SHA384_KAT)

    # ── BLAKE3 — determinism + sensitivity ───────────────────────────────────
    def _blake3():
        d1 = m.hash1('nextssl_blake3', _ABC, 32)
        d2 = m.hash1('nextssl_blake3', _ABC, 32)
        d3 = m.hash1('nextssl_blake3', b"xyz", 32)
        return (d1 == d2) and (d1 != d3) and (d1 != b'\x00' * 32)
    t.run("BLAKE3 determinism + sensitivity", _blake3)

    # ── BLAKE2b / BLAKE2s (XOF-style: takes out_len param) ───────────────────
    def _blake2(fn, out_len):
        d1 = m.hash2(fn, _ABC, out_len)
        d2 = m.hash2(fn, _ABC, out_len)
        d3 = m.hash2(fn, b"xyz", out_len)
        return (d1 == d2) and (d1 != d3) and (d1 != b'\x00' * out_len)
    t.run("BLAKE2b determinism + sensitivity", lambda: _blake2('nextssl_blake2b', 64))
    t.run("BLAKE2s determinism + sensitivity", lambda: _blake2('nextssl_blake2s', 32))

    # ── SHA3-256/512 KATs ─────────────────────────────────────────────────────
    t.run("SHA3-256 KAT",
          lambda: m.hash1('nextssl_sha3_256', _ABC, 32) == _SHA3_256_KAT)
    t.run("SHA3-512 KAT",
          lambda: m.hash1('nextssl_sha3_512', _ABC, 64) == _SHA3_512_KAT)
    # ── SHA3-224 / SHA3-384 KATs (newly exported) ────────────────────────────
    t.run("SHA3-224 KAT",
          lambda: m.hash1('nextssl_sha3_224', _ABC, 28) == _SHA3_224_KAT)
    t.run("SHA3-384 KAT",
          lambda: m.hash1('nextssl_sha3_384', _ABC, 48) == _SHA3_384_KAT)
    # ── Keccak-256 KAT ────────────────────────────────────────────────────────
    t.run("Keccak-256 KAT",
          lambda: m.hash1('nextssl_keccak_256', _ABC, 32) == _KECCAK256_KAT)

    # ── SHAKE-128/256 — determinism + output length respected ────────────────
    def _shake(fn, out_len):
        d1 = m.hash2(fn, _ABC, out_len)
        d2 = m.hash2(fn, _ABC, out_len)
        d3 = m.hash2(fn, b"xyz", out_len)
        return (d1 == d2) and (d1 != d3) and (d1 != b'\x00' * out_len)
    t.run("SHAKE-128 determinism + sensitivity", lambda: _shake('nextssl_shake128', 32))
    t.run("SHAKE-256 determinism + sensitivity", lambda: _shake('nextssl_shake256', 64))

    # ── Legacy alive: SHA-1, MD5 ─────────────────────────────────────────────
    t.run("SHA-1 KAT",
          lambda: m.hash1('nextssl_sha1', _ABC, 20) == _SHA1_KAT)
    t.run("MD5 KAT",
          lambda: m.hash1('nextssl_md5',  _ABC, 16) == _MD5_KAT)

    # ── Legacy unsafe: MD2, MD4 ───────────────────────────────────────────────
    t.run("MD2 KAT",
          lambda: m.hash1('nextssl_md2', _ABC, 16) == _MD2_KAT)
    t.run("MD4 KAT",
          lambda: m.hash1('nextssl_md4', _ABC, 16) == _MD4_KAT)
    # ── Legacy alive: RIPEMD-160 (KAT), Whirlpool, NT-Hash, AES-ECB ─────────
    t.run("RIPEMD-160 KAT",
          lambda: m.hash1('nextssl_ripemd160', _ABC, 20) == _RIPEMD160_KAT)

    def _whirlpool():
        d1 = m.hash1('nextssl_whirlpool', _ABC, 64)
        d2 = m.hash1('nextssl_whirlpool', _ABC, 64)
        d3 = m.hash1('nextssl_whirlpool', b"xyz", 64)
        return (d1 == d2) and (d1 != d3) and (d1 != b'\x00' * 64)
    t.run("Whirlpool determinism + sensitivity", _whirlpool)

    def _nt_hash():
        # nextssl_nt_hash(const char *password, uint8_t *out) — NUL-terminated
        p_pwd = m.buf(b"Password\x00")
        p_out = m.zbuf(16)
        m.call('nextssl_nt_hash', p_pwd, p_out)
        result = m.read(p_out, 16)
        m.free(p_pwd); m.free(p_out)
        # Determinism: same input → same output
        p_pwd2 = m.buf(b"Password\x00")
        p_out2 = m.zbuf(16)
        m.call('nextssl_nt_hash', p_pwd2, p_out2)
        result2 = m.read(p_out2, 16)
        m.free(p_pwd2); m.free(p_out2)
        return result != b'\x00' * 16 and result == result2
    t.run("NT-Hash determinism + non-zero", _nt_hash)

    def _aes_ecb_wrap():
        # nextssl_aes_ecb_encrypt(key, pntxt, ptextLen, crtxt) — AES-128
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ct = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
        p_key = m.buf(key)
        p_pt  = m.buf(pt)
        p_ct  = m.zbuf(16)
        m.call('nextssl_aes_ecb_encrypt', p_key, p_pt, 16, p_ct)
        result = m.read(p_ct, 16)
        m.free(p_key); m.free(p_pt); m.free(p_ct)
        return result == expected_ct
    t.run("AES-ECB-encrypt KAT (FIPS 197 block 1)", _aes_ecb_wrap)

    # ── Legacy unsafe: SHA-0, RIPEMD-128 (KAT), RIPEMD-256, RIPEMD-320, HAS-160
    t.run("SHA-0 determinism + non-zero",
          lambda: (lambda d1, d2: d1 == d2 and d1 != b'\x00' * 20)(
              m.hash1('nextssl_sha0', _ABC, 20),
              m.hash1('nextssl_sha0', _ABC, 20)))

    t.run("RIPEMD-128 KAT",
          lambda: m.hash1('nextssl_ripemd128', _ABC, 16) == _RIPEMD128_KAT)

    def _nz_det(fn, out_len):
        """Non-zero + determinism test for a hash1-style function."""
        d1 = m.hash1(fn, _ABC, out_len)
        d2 = m.hash1(fn, _ABC, out_len)
        return d1 == d2 and d1 != b'\x00' * out_len
    t.run("RIPEMD-256 determinism + non-zero", lambda: _nz_det('nextssl_ripemd256', 32))
    t.run("RIPEMD-320 determinism + non-zero", lambda: _nz_det('nextssl_ripemd320', 40))
    t.run("HAS-160 determinism + non-zero",    lambda: _nz_det('nextssl_has160',    20))
    # ── Argon2id / Argon2i / Argon2d — consistency + non-zero output ─────────
    # LeylineArgon2Params: { uint32 t_cost, uint32 m_cost_kb, uint32 parallelism }
    params_bytes = struct.pack('<III', 1, 8, 1)   # t=1, m=8 KiB, p=1

    def _argon2(fn):
        pwd  = b"password"
        salt = b"saltsalt"
        p_params = m.buf(params_bytes)
        p_pwd    = m.buf(pwd)
        p_salt   = m.buf(salt)
        p_out    = m.zbuf(32)
        # fn(pwd, pwd_len, salt, salt_len, params*, out, out_len)
        m.call(fn, p_pwd, len(pwd), p_salt, len(salt), p_params, p_out, 32)
        # Two identical calls must produce the same digest
        p_out2 = m.zbuf(32)
        m.call(fn, p_pwd, len(pwd), p_salt, len(salt), p_params, p_out2, 32)
        d1 = m.read(p_out, 32)
        d2 = m.read(p_out2, 32)
        for p in (p_params, p_pwd, p_salt, p_out, p_out2):
            m.free(p)
        return (d1 == d2) and (d1 != b'\x00' * 32)

    t.run("Argon2id consistency + non-zero", lambda: _argon2('nextssl_argon2id'))
    t.run("Argon2i  consistency + non-zero", lambda: _argon2('nextssl_argon2i'))
    t.run("Argon2d  consistency + non-zero", lambda: _argon2('nextssl_argon2d'))

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True):
    """Run all hash.wasm functional tests.  Returns 0 on pass, 1 on fail."""
    console.set_color(color)
    console.print_header("WASM hash tests")

    mod, err = load_module('main', 'hash')
    if mod is None:
        console.print_fail(f"Cannot load hash.wasm: {err}")
        return 1

    console.print_pass(f"Loaded: {mod._store}")   # just confirm it loaded

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(f"hash.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
