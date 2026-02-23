import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, console

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
        config = Config()
        DLL_PATH = config.get_lib_path('partial', 'legacy_alive', 'dhcm')

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

        # ---------------------------------------------------------
        # MD5 Test
        # ---------------------------------------------------------
        console.print_step("Testing MD5")
        params = DHCMParams(
            algorithm=0x0400, # DHCM_MD5
            input_size=32,
            output_size=16
        )
        res = DHCMResult()
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            if res.work_units_per_eval == 500:
                console.print_pass("MD5 (32B)")
                print(f"       WU: {res.work_units_per_eval}")
                passed += 1
            else:
                console.print_fail(f"MD5 mismatch. Expected 500, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("MD5 calculation failed")
            failed += 1

        # ---------------------------------------------------------
        # SHA-1 Test
        # ---------------------------------------------------------
        console.print_step("Testing SHA-1")
        params.algorithm = 0x0401 # DHCM_SHA1
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            if res.work_units_per_eval == 900:
                console.print_pass("SHA-1 (32B)")
                print(f"       WU: {res.work_units_per_eval}")
                passed += 1
            else:
                console.print_fail(f"SHA-1 mismatch. Expected 900, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("SHA-1 calculation failed")
            failed += 1

        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM Legacy Alive: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM Legacy Alive: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
