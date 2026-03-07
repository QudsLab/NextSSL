"""
script/web/pow.py — WASM functional tests for pow.wasm (main tier).

Tests the full PoW challenge / solve / verify flow using Python structs
serialised into WASM linear memory.

POWConfig / POWChallenge / POWSolution struct layouts are replicated here
using Python struct.pack with the WASM32 ABI offsets (all pointers = i32,
size_t = i32, standard C alignment).

Struct offsets (WASM32):
  POWConfig   — 164 bytes  (see below)
  POWChallenge — 416 bytes
  POWSolution — 112 bytes
"""
import os
import sys
import struct as _struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module


# ─────────────────────────────────────────────────────────────────────────────
# WASM32 struct helpers
# ─────────────────────────────────────────────────────────────────────────────

def _zeroed(n: int) -> bytearray:
    return bytearray(n)


def _write_u32(buf: bytearray, offset: int, v: int):
    _struct.pack_into('<I', buf, offset, v & 0xFFFFFFFF)


def _write_u64(buf: bytearray, offset: int, v: int):
    _struct.pack_into('<Q', buf, offset, v & 0xFFFFFFFFFFFFFFFF)


def _write_ptr(buf: bytearray, offset: int, ptr: int):
    """Write a WASM32 pointer (i32) at offset."""
    _struct.pack_into('<I', buf, offset, ptr & 0xFFFFFFFF)


def _read_ptr(buf: bytes, offset: int) -> int:
    return _struct.unpack_from('<I', buf, offset)[0]


def _read_u64(buf: bytes, offset: int) -> int:
    return _struct.unpack_from('<Q', buf, offset)[0]


def _read_f64(buf: bytes, offset: int) -> float:
    return _struct.unpack_from('<d', buf, offset)[0]


# ─────────────────────────────────────────────────────────────────────────────
# POWConfig (164 bytes in WASM32)
#
#  +0   uint32_t  default_difficulty_bits
#  +4   [4 pad]
#  +8   uint64_t  max_wu_per_challenge
#  +16  uint64_t  challenge_ttl_seconds
#  +24  char*[32] allowed_algos          (32 × 4 = 128 bytes)
#  +152 size_t    allowed_algos_count    (4 bytes)
#  +156 uint32_t  max_challenges_per_ip
#  +160 uint32_t  rate_limit_window_seconds
#  = 164 bytes total
# ─────────────────────────────────────────────────────────────────────────────

_POW_CONFIG_SIZE = 164

def _make_pow_config(mod, difficulty_bits: int, algos: list) -> tuple:
    """
    Build a POWConfig in WASM memory.
    Returns (config_ptr, list_of_algo_ptrs_to_free).
    """
    m = mod
    # Write each algo string into WASM memory
    algo_ptrs = []
    for name in algos:
        p = m.buf(name.encode() + b'\x00')
        algo_ptrs.append(p)

    buf = _zeroed(_POW_CONFIG_SIZE)
    _write_u32(buf,  0, difficulty_bits)
    # +4: 4 bytes padding
    _write_u64(buf,  8, 0xFFFFFFFFFFFFFFFF)   # max_wu = unlimited
    _write_u64(buf, 16, 3600)                  # ttl = 1 hour
    for i, p in enumerate(algo_ptrs[:32]):
        _write_ptr(buf, 24 + i * 4, p)
    _write_u32(buf, 152, len(algos))
    # max_challenges_per_ip = 0, rate_limit_window_seconds = 0 (already zero)

    cfg_ptr = m.buf(bytes(buf))
    return cfg_ptr, algo_ptrs


# ─────────────────────────────────────────────────────────────────────────────
# POWChallenge (416 bytes in WASM32)
#
#  +0    uint8_t  version             (1)
#  +1    uint8_t  challenge_id[16]    (16)
#  +17   char     algorithm_id[32]    (32)
#  +49   uint8_t  context[256]        (256)
#  +305  [3 pad]
#  +308  size_t   context_len         (4)
#  +312  uint8_t  target[64]          (64)
#  +376  size_t   target_len          (4)
#  +380  uint32_t difficulty_bits     (4)
#  +384  uint64_t wu                  (8)
#  +392  uint64_t mu                  (8)
#  +400  uint64_t expires_unix        (8)
#  +408  void*    algo_params         (4)
#  +412  size_t   algo_params_size    (4)
#  = 416 bytes
# ─────────────────────────────────────────────────────────────────────────────

_POW_CHALLENGE_SIZE = 416


# ─────────────────────────────────────────────────────────────────────────────
# POWSolution (112 bytes in WASM32)
#
#  +0   uint8_t  challenge_id[16]    (16)
#  +16  uint64_t nonce               (8)
#  +24  uint8_t  hash_output[64]     (64)
#  +88  size_t   hash_output_len     (4)
#  +92  [4 pad]
#  +96  double   solve_time_seconds  (8)
#  +104 uint64_t attempts            (8)
#  = 112 bytes
# ─────────────────────────────────────────────────────────────────────────────

_POW_SOLUTION_SIZE = 112


# ─────────────────────────────────────────────────────────────────────────────

def _run_tests(mod) -> _Tester:
    t = _Tester()
    m = mod

    # ── Full PoW flow: generate → check_limits → solve → verify ─────────────
    # difficulty=4 bits → ~16 expected trials, very fast in WASM
    def _pow_flow():
        cfg_ptr, algo_ptrs = _make_pow_config(m, difficulty_bits=4,
                                              algos=["sha256"])
        challenge_ptr = m.zbuf(_POW_CHALLENGE_SIZE)
        solution_ptr  = m.zbuf(_POW_SOLUTION_SIZE)

        # Allocate algo_id string for generate call
        p_algo = m.buf(b"sha256\x00")

        # nextssl_pow_server_generate_challenge(config, algorithm_id,
        #   ctx, ctx_len, difficulty_bits, challenge_out)  → int (0 = ok)
        rc = m.call('nextssl_pow_server_generate_challenge',
                    cfg_ptr, p_algo, 0, 0, 4, challenge_ptr)
        if rc != 0:
            return False

        # nextssl_pow_client_check_limits(challenge, max_wu, max_mu,
        #   max_time_s, out_ok*)  → int
        p_ok = m.zbuf(4)
        m.call('nextssl_pow_client_check_limits',
               challenge_ptr,
               0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
               60.0, p_ok)
        # (ignore result; proceed to solve regardless)

        # nextssl_pow_client_solve(challenge, solution_out)  → int (0 = ok)
        rc = m.call('nextssl_pow_client_solve', challenge_ptr, solution_ptr)
        if rc != 0:
            return False

        # nextssl_pow_server_verify_solution(challenge, solution,
        #   out_valid*)  → int (0 = ok)
        p_valid = m.zbuf(4)
        rc = m.call('nextssl_pow_server_verify_solution',
                    challenge_ptr, solution_ptr, p_valid)
        if rc != 0:
            return False

        valid_flag = _struct.unpack_from('<I', bytes(m.read(p_valid, 4)))[0]

        # Clean up
        for p in [cfg_ptr, challenge_ptr, solution_ptr, p_algo, p_ok, p_valid]:
            m.free(p)
        for p in algo_ptrs:
            m.free(p)

        return valid_flag != 0

    t.run("PoW SHA-256 challenge/solve/verify (difficulty=4)", _pow_flow)

    return t


# ─────────────────────────────────────────────────────────────────────────────

def main(color=True):
    """Run all pow.wasm functional tests.  Returns 0 on pass, 1 on fail."""
    console.set_color(color)
    console.print_header("WASM pow tests")

    mod, err = load_module('main', 'pow')
    if mod is None:
        console.print_fail(f"Cannot load pow.wasm: {err}")
        return 1

    t = _run_tests(mod)

    print(f"\n{'=' * 50}")
    console.print_info(f"pow.wasm — {t.passed} passed, {t.failed} failed")
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
