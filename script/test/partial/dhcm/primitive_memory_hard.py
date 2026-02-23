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
        DLL_PATH = config.get_lib_path('partial', 'primitive_memory_hard', 'dhcm')

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
            console.log_data(f"{name}.mu", res.memory_units_per_eval)

        # ---------------------------------------------------------
        # Argon2id Low Memory Test
        # ---------------------------------------------------------
        console.print_step("Testing Argon2id (Low Memory)")
        params = DHCMParams(
            algorithm=0x0200, # DHCM_ARGON2ID
            difficulty_model=2, # ITERATION_BASED
            iterations=3,
            memory_kb=4096,
            parallelism=1,
            input_size=32,
            output_size=32
        )
        res = DHCMResult()
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            # Expected WU = 3 * 4096 * 1 * 800 = 9,830,400
            expected_wu = 3 * 4096 * 1 * 800
            if res.work_units_per_eval == expected_wu:
                console.print_pass("Argon2id Low Mem")
                print(f"       WU: {res.work_units_per_eval}")
                print(f"       MU: {res.memory_units_per_eval} KB")
                log_result("Argon2id_Low", res)
                passed += 1
            else:
                console.print_fail(f"Argon2id Low Mem mismatch. Expected {expected_wu}, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("Argon2id calculation failed")
            failed += 1

        # ---------------------------------------------------------
        # Argon2id High Memory Test
        # ---------------------------------------------------------
        console.print_step("Testing Argon2id (High Memory)")
        params.memory_kb = 65536
        params.parallelism = 4
        
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
            # Expected WU = 3 * 65536 * 4 * 800 = 629,145,600
            expected_wu = 3 * 65536 * 4 * 800
            if res.work_units_per_eval == expected_wu:
                console.print_pass("Argon2id High Mem")
                print(f"       WU: {res.work_units_per_eval}")
                log_result("Argon2id_High", res)
                passed += 1
            else:
                console.print_fail(f"Argon2id High Mem mismatch. Expected {expected_wu}, got {res.work_units_per_eval}")
                failed += 1
        else:
            console.print_fail("Argon2id High Mem calculation failed")
            failed += 1

        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM MemHard: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM MemHard: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
