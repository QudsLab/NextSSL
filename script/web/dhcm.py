# -*- coding: utf-8 -*-
"""
script/web/dhcm.py — WASM functional tests for dhcm.wasm (main tier).

Covers ALL 3 exported functions in _WASM_DHCM_EXPORTS:
  nextssl_dhcm_expected_trials,
  nextssl_dhcm_calculate,
  nextssl_dhcm_get_algorithm_info
"""
import os
import sys
import struct as _struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console
from script.web._base import _Tester, load_module

# ── DHCM algorithm IDs ────────────────────────────────────────────────────────
DHCM_SHA256   = 0x0100
DHCM_SHA512   = 0x0101
DHCM_ARGON2ID = 0x0200

# DHCMDifficultyModel enum
DHCM_MODEL_BASIC    = 0
DHCM_MODEL_BIRTHDAY = 1

# DHCMParams struct layout (WASM32) — 64 bytes:
#   algorithm   @ 0   (u32)
#   model       @ 4   (u32)
#   zeros       @ 8   (u32)    target zero bits
#   input_size  @ 12  (u32)
#   output_size @ 16  (u32)
#   pad         @ 20 … 63
_DHCM_PARAMS_SIZE = 64

# DHCMResult struct layout (WASM32) — 64 bytes:
#   wu     @ 0  (u64)   work units
#   trials @ 8  (f64)   expected trials
_DHCM_RESULT_SIZE = 64


def _make_params(algorithm: int, model: int, zeros: int,
                 input_size: int, output_size: int) -> bytes:
    buf = bytearray(_DHCM_PARAMS_SIZE)
    _struct.pack_into('<I', buf, 0,  algorithm)
    _struct.pack_into('<I', buf, 4,  model)
    _struct.pack_into('<I', buf, 8,  zeros)
    _struct.pack_into('<I', buf, 12, input_size)
    _struct.pack_into('<I', buf, 16, output_size)
    return bytes(buf)


def _run_tests(m) -> _Tester:
    t = _Tester()

    # ══════════════════════════════════════════════════════════════════════════
    # A — nextssl_dhcm_expected_trials
    # double nextssl_dhcm_expected_trials(DHCMDifficultyModel model, uint32_t zeros) → >0
    # ══════════════════════════════════════════════════════════════════════════

    def _expected_trials_basic():
        result = m.call('nextssl_dhcm_expected_trials', DHCM_MODEL_BASIC, 8)
        return isinstance(result, float) and result > 0.0

    t.run("nextssl_dhcm_expected_trials (basic, zeros=8) > 0", _expected_trials_basic)

    def _expected_trials_birthday():
        result = m.call('nextssl_dhcm_expected_trials', DHCM_MODEL_BIRTHDAY, 8)
        return isinstance(result, float) and result > 0.0

    t.run("nextssl_dhcm_expected_trials (birthday, zeros=8) > 0", _expected_trials_birthday)

    # ══════════════════════════════════════════════════════════════════════════
    # B — nextssl_dhcm_calculate
    # int nextssl_dhcm_calculate(const DHCMParams *params, DHCMResult *result) → 0
    # ══════════════════════════════════════════════════════════════════════════

    def _calculate_sha256():
        p_params = m.buf(_make_params(DHCM_SHA256, DHCM_MODEL_BASIC, 8, 64, 32))
        p_result = m.zbuf(_DHCM_RESULT_SIZE)
        rc = m.call('nextssl_dhcm_calculate', p_params, p_result)
        result_bytes = m.read(p_result, _DHCM_RESULT_SIZE)
        m.free(p_params); m.free(p_result)
        if rc != 0:
            return False
        wu = _struct.unpack_from('<Q', result_bytes, 0)[0]
        return wu > 0

    t.run("nextssl_dhcm_calculate SHA-256 (zeros=8) wu > 0", _calculate_sha256)

    def _calculate_sha512():
        p_params = m.buf(_make_params(DHCM_SHA512, DHCM_MODEL_BASIC, 4, 64, 64))
        p_result = m.zbuf(_DHCM_RESULT_SIZE)
        rc = m.call('nextssl_dhcm_calculate', p_params, p_result)
        m.free(p_params); m.free(p_result)
        return rc == 0

    t.run("nextssl_dhcm_calculate SHA-512 (zeros=4) rc == 0", _calculate_sha512)

    def _calculate_argon2id():
        p_params = m.buf(_make_params(DHCM_ARGON2ID, DHCM_MODEL_BASIC, 4, 32, 32))
        p_result = m.zbuf(_DHCM_RESULT_SIZE)
        rc = m.call('nextssl_dhcm_calculate', p_params, p_result)
        m.free(p_params); m.free(p_result)
        return rc == 0

    t.run("nextssl_dhcm_calculate Argon2id (zeros=4) rc == 0", _calculate_argon2id)

    # ══════════════════════════════════════════════════════════════════════════
    # C — nextssl_dhcm_get_algorithm_info
    # int nextssl_dhcm_get_algorithm_info(algo, name**, wu*, block_size*) → 0
    # ══════════════════════════════════════════════════════════════════════════

    def _algo_info_sha256():
        p_name       = m.zbuf(4)   # receives pointer to string literal
        p_base_wu    = m.zbuf(8)   # u64
        p_block_size = m.zbuf(8)   # size_t
        rc = m.call('nextssl_dhcm_get_algorithm_info', DHCM_SHA256,
                    p_name, p_base_wu, p_block_size)
        m.free(p_name); m.free(p_base_wu); m.free(p_block_size)
        return rc == 0

    t.run("nextssl_dhcm_get_algorithm_info SHA-256 rc == 0", _algo_info_sha256)

    def _algo_info_sha512():
        p_name       = m.zbuf(4)
        p_base_wu    = m.zbuf(8)
        p_block_size = m.zbuf(8)
        rc = m.call('nextssl_dhcm_get_algorithm_info', DHCM_SHA512,
                    p_name, p_base_wu, p_block_size)
        m.free(p_name); m.free(p_base_wu); m.free(p_block_size)
        return rc == 0

    t.run("nextssl_dhcm_get_algorithm_info SHA-512 rc == 0", _algo_info_sha512)

    def _algo_info_argon2id():
        p_name       = m.zbuf(4)
        p_base_wu    = m.zbuf(8)
        p_block_size = m.zbuf(8)
        rc = m.call('nextssl_dhcm_get_algorithm_info', DHCM_ARGON2ID,
                    p_name, p_base_wu, p_block_size)
        m.free(p_name); m.free(p_base_wu); m.free(p_block_size)
        return rc == 0

    t.run("nextssl_dhcm_get_algorithm_info Argon2id rc == 0", _algo_info_argon2id)

    return t


def main() -> int:
    """Entry point called by runner.py via _MODULE_REGISTRY."""
    m, err = load_module('main', 'dhcm')
    if m is None:
        console.print_fail(f"dhcm.wasm load failed: {err}")
        return 1

    t = _run_tests(m)
    total = t.passed + t.failed
    console.print_info(f"dhcm WASM tests: {t.passed}/{total} passed")
    return 0 if t.failed == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
