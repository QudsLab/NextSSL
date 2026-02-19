import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import console

# Structs
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
    try:
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'dhcm', 'primitive_sponge_xof.dll')

        console.print_step(f"Loading {DLL_PATH}")
        if not os.path.exists(DLL_PATH):
            console.print_fail(f"DLL not found: {DLL_PATH}")
            return 1
            
        lib = ctypes.CDLL(DLL_PATH)
        console.print_pass("DLL Loaded")

        lib.leyline_dhcm_calculate.argtypes = [ctypes.POINTER(DHCMParams), ctypes.POINTER(DHCMResult)]
        lib.leyline_dhcm_calculate.restype = ctypes.c_int

        passed = 0
        failed = 0

        def log_result(name, res):
            console.log_data(f"{name}.algo", res.algorithm_name.decode('utf-8'))
            console.log_data(f"{name}.wu", res.work_units_per_eval)

        # ---------------------------------------------------------
        # SHA3-256 Test
        # ---------------------------------------------------------
        console.print_step("Testing SHA3-256 (64B)")
        params = DHCMParams(
            algorithm=0x0300, # DHCM_SHA3_256
            input_size=64,
            output_size=32
        )
        res = DHCMResult()
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            # 1 block -> 1500 WU
            if res.work_units_per_eval == 1500:
                console.print_pass("SHA3-256 (64B)")
                print(f"       WU: {res.work_units_per_eval}")
                log_result("SHA3_256", res)
                passed += 1
            else:
                console.print_fail(f"SHA3-256 mismatch. Expected 1500, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("SHA3-256 calculation failed")
            failed += 1

        # ---------------------------------------------------------
        # SHAKE-128 Test (XOF Squeezing)
        # ---------------------------------------------------------
        console.print_step("Testing SHAKE-128 (200B Output)")
        params.algorithm = 0x0303 # DHCM_SHAKE128
        params.input_size = 32
        params.output_size = 200 # > 168 (Rate)
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            # Absorb: 1 block (32 <= 168)
            # Squeeze: 200 > 168. Extra squeeze needed.
            # Total: 1 absorb + 1 squeeze = 2 ops.
            # Base 1400 * 2 = 2800 WU.
            if res.work_units_per_eval == 2800:
                console.print_pass("SHAKE-128 (200B)")
                print(f"       WU: {res.work_units_per_eval}")
                log_result("SHAKE128", res)
                passed += 1
            else:
                console.print_fail(f"SHAKE-128 mismatch. Expected 2800, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("SHAKE-128 calculation failed")
            failed += 1

        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM Sponge: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM Sponge: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
