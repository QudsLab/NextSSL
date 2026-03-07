"""
test/main/pow.py
────────────────
Main-tier tests for the merged PoW + DHCM module.
Covers the single pow DLL (server+client merged) and dhcm.
"""
import ctypes
import os
import sys
import time
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, console

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def leading_zero_bits(data):
    count = 0
    for b in data:
        if b == 0:
            count += 8
            continue
        for i in range(8):
            if b & (0x80 >> i):
                return count + i
        return count + 8
    return count

def bytes_to_bin(data):
    return " ".join(f"{b:08b}" for b in data)

def prefix_bits(data, bits):
    if bits <= 0:
        return ""
    return "".join(f"{b:08b}" for b in data)[:bits]

# ─────────────────────────────────────────────────────────────────────────────
# PoW ctypes structures
# ─────────────────────────────────────────────────────────────────────────────

class POWChallenge(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint8),
        ("challenge_id", ctypes.c_uint8 * 16),
        ("algorithm_id", ctypes.c_char * 32),
        ("context", ctypes.c_uint8 * 256),
        ("context_len", ctypes.c_size_t),
        ("target", ctypes.c_uint8 * 64),
        ("target_len", ctypes.c_size_t),
        ("difficulty_bits", ctypes.c_uint32),
        ("wu", ctypes.c_uint64),
        ("mu", ctypes.c_uint64),
        ("expires_unix", ctypes.c_uint64),
        ("algo_params", ctypes.c_void_p),
        ("algo_params_size", ctypes.c_size_t)
    ]

class POWSolution(ctypes.Structure):
    _fields_ = [
        ("challenge_id", ctypes.c_uint8 * 16),
        ("nonce", ctypes.c_uint64),
        ("hash_output", ctypes.c_uint8 * 64),
        ("hash_output_len", ctypes.c_size_t),
        ("solve_time_seconds", ctypes.c_double),
        ("attempts", ctypes.c_uint64)
    ]

class POWConfig(ctypes.Structure):
    _fields_ = [
        ("default_difficulty_bits", ctypes.c_uint32),
        ("max_wu_per_challenge", ctypes.c_uint64),
        ("challenge_ttl_seconds", ctypes.c_uint64),
        ("allowed_algos", ctypes.c_char_p * 32),
        ("allowed_algos_count", ctypes.c_size_t),
        ("max_challenges_per_ip", ctypes.c_uint32),
        ("rate_limit_window_seconds", ctypes.c_uint32)
    ]

# ─────────────────────────────────────────────────────────────────────────────
# DHCM ctypes structures
# ─────────────────────────────────────────────────────────────────────────────

class DHCMParams(ctypes.Structure):
    _fields_ = [
        ("algorithm", ctypes.c_uint32),
        ("difficulty_model", ctypes.c_uint32),
        ("target_leading_zeros", ctypes.c_uint32),
        ("iterations", ctypes.c_uint32),
        ("memory_kb", ctypes.c_uint32),
        ("parallelism", ctypes.c_uint32),
        ("input_size", ctypes.c_size_t),
        ("output_size", ctypes.c_size_t),
    ]

class DHCMResult(ctypes.Structure):
    _fields_ = [
        ("work_units_per_eval", ctypes.c_uint64),
        ("memory_units_per_eval", ctypes.c_uint64),
        ("expected_trials", ctypes.c_double),
        ("total_work_units", ctypes.c_uint64),
        ("total_memory_units", ctypes.c_uint64),
        ("verification_work_units", ctypes.c_uint64),
        ("algorithm_name", ctypes.c_char_p),
        ("cost_model_version", ctypes.c_char_p),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# PoW challenge/solve/verify loop (used by both pair and combined)
# ─────────────────────────────────────────────────────────────────────────────

def _pow_generate_sign(server_lib, client_lib, algos, difficulty=1):
    """Run challenge→solve→verify for each algo. Returns True if all pass."""
    cfg = POWConfig()
    cfg.default_difficulty_bits = difficulty
    cfg.max_wu_per_challenge = 10**10
    cfg.challenge_ttl_seconds = 60

    success = True
    for algo in algos:
        console.print_step(f"Testing {algo} (d={difficulty})...")
        challenge = POWChallenge()
        context = (ctypes.c_uint8 * 32)(*([0x00] * 32))

        ret = server_lib.nextssl_pow_server_generate_challenge(
            ctypes.byref(cfg), algo.encode('utf-8'), context, 32, difficulty, ctypes.byref(challenge)
        )
        if ret != 0:
            console.print_fail(f"Generate failed: {algo}", expected=0, got=ret)
            success = False
            continue

        solution = POWSolution()
        result_box = {'ret': -1}
        def _solve():
            result_box['ret'] = client_lib.nextssl_pow_client_solve(
                ctypes.byref(challenge), ctypes.byref(solution)
            )
        t = threading.Thread(target=_solve, daemon=True)
        t.start()
        t.join(timeout=10.0)

        if t.is_alive():
            console.print_fail(f"Watchdog timeout: {algo}")
            success = False
            continue
        if result_box['ret'] != 0:
            console.print_fail(f"Solve failed: {algo}", expected=0, got=result_box['ret'])
            success = False
            continue

        lz = leading_zero_bits(bytes(solution.hash_output[:solution.hash_output_len]))
        if lz < challenge.difficulty_bits:
            console.print_fail(f"Difficulty check failed: {algo}", expected=challenge.difficulty_bits, got=lz)
            success = False
            continue

        is_valid = ctypes.c_bool(False)
        ret = server_lib.nextssl_pow_server_verify_solution(
            ctypes.byref(challenge), ctypes.byref(solution), ctypes.byref(is_valid)
        )
        if ret != 0 or not is_valid.value:
            console.print_fail(f"Verify failed: {algo}")
            success = False
        else:
            console.print_pass(f"{algo} OK")

    return success

_POW_ALGOS = [
    'sha256', 'sha512', 'blake3', 'blake2b', 'blake2s',
    'argon2id', 'argon2i', 'argon2d',
    'shake128', 'shake256', 'sha3_256', 'sha3_512', 'keccak_256',
    'md5', 'sha1', 'ripemd160', 'whirlpool', 'nt',
    'md2', 'md4', 'sha0', 'has160', 'ripemd128', 'ripemd256', 'ripemd320',
]

def _setup_pow_server_signatures(lib):
    """Assign argtypes/restype for server-side PoW functions."""
    lib.nextssl_pow_server_generate_challenge.argtypes = [
        ctypes.POINTER(POWConfig), ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(POWChallenge)
    ]
    lib.nextssl_pow_server_generate_challenge.restype = ctypes.c_int
    lib.nextssl_pow_server_verify_solution.argtypes = [
        ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution), ctypes.POINTER(ctypes.c_bool)
    ]
    lib.nextssl_pow_server_verify_solution.restype = ctypes.c_int

def _setup_pow_client_signatures(lib):
    """Assign argtypes/restype for client-side PoW functions."""
    lib.nextssl_pow_client_solve.argtypes = [
        ctypes.POINTER(POWChallenge), ctypes.POINTER(POWSolution)
    ]
    lib.nextssl_pow_client_solve.restype = ctypes.c_int

def _setup_pow_signatures(lib, is_combined=False):
    """Assign argtypes/restype for the PoW API (combined DLL has both sides)."""
    _setup_pow_server_signatures(lib)
    _setup_pow_client_signatures(lib)

# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — pow_server / pow_client pair
# ─────────────────────────────────────────────────────────────────────────────

def load_dll_pair():
    config = Config()
    pow_path = config.get_lib_path('main', 'pow')
    if not os.path.exists(pow_path):
        console.print_warn(f"Skipping PoW pair: DLL not found")
        return None, None
    try:
        lib = ctypes.CDLL(pow_path)
        _setup_pow_server_signatures(lib)
        _setup_pow_client_signatures(lib)
        return lib, lib
    except Exception as e:
        console.print_fail(f"Error loading PoW DLL: {e}")
        return None, None

def _test_pow_pair():
    console.print_header("── PoW pair (server+client) ──")
    server, client = load_dll_pair()
    if server is None:
        return True  # skip gracefully
    ok = True
    for diff in [1, 4]:
        if not _pow_generate_sign(server, client, _POW_ALGOS, difficulty=diff):
            ok = False
    return ok

# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — pow_combined single DLL
# ─────────────────────────────────────────────────────────────────────────────

def _test_pow_combined():
    console.print_header("── PoW combined (single DLL) ──")
    config = Config()
    dll_path = config.get_lib_path('main', 'pow')
    if not os.path.exists(dll_path):
        console.print_warn("Skipping pow combined: DLL not found")
        return True
    try:
        lib = ctypes.CDLL(dll_path)
        _setup_pow_signatures(lib, is_combined=True)
    except Exception as e:
        console.print_fail(f"Error loading pow DLL: {e}")
        return False

    ok = True
    for diff in [1, 4]:
        if not _pow_generate_sign(lib, lib, _POW_ALGOS, difficulty=diff):
            ok = False
    return ok

# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — dhcm
# ─────────────────────────────────────────────────────────────────────────────

def _test_dhcm():
    console.print_header("── DHCM ──")
    config = Config()
    dll_path = config.get_lib_path('main', 'dhcm')
    if not os.path.exists(dll_path):
        console.print_warn("Skipping dhcm: DLL not found")
        return True
    try:
        lib = ctypes.CDLL(dll_path)
        lib.nextssl_dhcm_calculate.argtypes = [
            ctypes.POINTER(DHCMParams), ctypes.POINTER(DHCMResult)
        ]
        lib.nextssl_dhcm_calculate.restype = ctypes.c_int
    except Exception as e:
        console.print_fail(f"Error loading dhcm: {e}")
        return False

    passed = 0
    failed = 0
    res = DHCMResult()

    def check(algo_id, input_len, expected_wu, name):
        nonlocal passed, failed
        params = DHCMParams(algorithm=algo_id, input_size=input_len)
        if algo_id == 0x0200:
            params.difficulty_model = 2
            params.iterations = 3
            params.memory_kb = 4096
            params.parallelism = 1
        if lib.nextssl_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            if res.work_units_per_eval == expected_wu:
                console.print_pass(f"DHCM {name} OK")
                passed += 1
            else:
                console.print_fail(f"DHCM {name}: expected {expected_wu}, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail(f"DHCM {name}: calculation error")
            failed += 1

    check(0x0100, 64,   2000,    "SHA-256")
    check(0x0200, 0,    9830400, "Argon2id")
    check(0x0300, 64,   1500,    "SHA3-256")
    check(0x0400, 32,   500,     "MD5")
    check(0x0500, 16,   2400,    "MD2")

    if failed == 0:
        console.print_pass(f"DHCM: {passed} passed")
        return True
    else:
        console.print_fail(f"DHCM: {failed} failed")
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    console.print_header("=== PoW + DHCM Main Tier Test ===")
    results = {
        'pair':     _test_pow_pair(),
        'combined': _test_pow_combined(),
        'dhcm':     _test_dhcm(),
    }
    failed = [k for k, v in results.items() if not v]
    if not failed:
        console.print_pass("All PoW+DHCM tests passed")
        return 0
    console.print_fail(f"Failed sections: {', '.join(failed)}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
