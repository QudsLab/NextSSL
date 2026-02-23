import ctypes
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, console

# ── Step 3: Define structs ──
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

def main():
    """Run tests for primitive_fast.dll."""
    try:
        # 1. Resolve DLL path
        config = Config()
        DLL_PATH = config.get_lib_path('partial', 'primitive_fast', 'dhcm')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        # Define function signatures
        lib.leyline_dhcm_calculate.argtypes = [ctypes.POINTER(DHCMParams), ctypes.POINTER(DHCMResult)]
        lib.leyline_dhcm_calculate.restype = ctypes.c_int

        passed = 0
        failed = 0

        # Helper to log
        def log_result(name, res):
            console.log_data(f"{name}.algo", res.algorithm_name.decode('utf-8'))
            console.log_data(f"{name}.wu_per_eval", res.work_units_per_eval)
            console.log_data(f"{name}.mu_per_eval", res.memory_units_per_eval)
            console.log_data(f"{name}.expected_trials", res.expected_trials)
            console.log_data(f"{name}.total_wu", res.total_work_units)

        # ---------------------------------------------------------
        # SHA-256 Test
        # ---------------------------------------------------------
        console.print_step("Testing SHA-256 Cost")
        params = DHCMParams(
            algorithm=0x0100, # DHCM_SHA256
            difficulty_model=0,
            input_size=64,
            output_size=32
        )
        res = DHCMResult()
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            # SHA-256 Base=1000, 64 bytes input -> 2 blocks -> 2000 WU (approx)
            # My formula: 1 + (64/64) = 2 blocks. 1000 * 2 = 2000 WU.
            if res.work_units_per_eval == 2000:
                console.print_pass("SHA-256 Cost (64B)")
                print(f"       WU: {res.work_units_per_eval}")
                log_result("SHA-256", res)
                passed += 1
            else:
                console.print_fail(f"SHA-256 Cost mismatch. Expected 2000, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("SHA-256 calculation failed")
            failed += 1

        # ---------------------------------------------------------
        # Target-Based Difficulty Test
        # ---------------------------------------------------------
        console.print_step("Testing Target-Based Difficulty (20 bits)")
        params.difficulty_model = 1 # DHCM_DIFFICULTY_TARGET_BASED
        params.target_leading_zeros = 20
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            expected_trials = 1048576.0 # 2^20
            if abs(res.expected_trials - expected_trials) < 1.0:
                console.print_pass("Target Difficulty (20 bits)")
                print(f"       Expected Trials: {res.expected_trials}")
                print(f"       Total WU:        {res.total_work_units}")
                log_result("TargetDiff", res)
                passed += 1
            else:
                console.print_fail(f"Expected Trials mismatch. Expected {expected_trials}, got {res.expected_trials}")
                failed += 1
        else:
            console.print_fail("Target Difficulty calculation failed")
            failed += 1

        # Summary
        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM Fast: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM Fast: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
