"""
script/web/hash.py — WASM functional tests for hash.wasm (main tier).

Covers every exported hash / XOF / KDF algorithm:
  SHA-256/512/224/384, SHA-256 streaming,
  BLAKE3, SHA3-256/512, Keccak-256,
  SHAKE-128/256, SHA-1, MD5, MD2, MD4,
  Argon2id / Argon2i / Argon2d

All KAT vectors are from FIPS 180-4, FIPS 202, RFC 1319–1321, or NIST.
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
_SHA3_256_KAT = bytes.fromhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
_SHA3_512_KAT = bytes.fromhex(
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712d"
    "a101cd941f6e22f62a2d2f8a1617e4eb75b8a7e9e2e955afa59e8e7c2cf0d99e")
_KECCAK256_KAT = bytes.fromhex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
_SHA1_KAT     = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
_MD5_KAT      = bytes.fromhex("900150983cd24fb0d6963f7d28e17f72")
_MD2_KAT      = bytes.fromhex("da853b0d3f88d99b30283a69e6ded6bb")
_MD4_KAT      = bytes.fromhex("a448017aaf21d8525fc10ae87aa6729d")


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

    # ── SHA3-256/512 KATs ─────────────────────────────────────────────────────
    t.run("SHA3-256 KAT",
          lambda: m.hash1('nextssl_sha3_256', _ABC, 32) == _SHA3_256_KAT)
    t.run("SHA3-512 KAT",
          lambda: m.hash1('nextssl_sha3_512', _ABC, 64) == _SHA3_512_KAT)

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
