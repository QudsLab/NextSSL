import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

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
        DLL_PATH = config.get_lib_path('main', 'dhcm')

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
        res = DHCMResult()

        def check(algo_id, input_len, expected_wu, name):
            nonlocal passed, failed
            params = DHCMParams(algorithm=algo_id, input_size=input_len)
            # For Argon2, need extra params
            if algo_id == 0x0200: 
                params.difficulty_model = 2
                params.iterations = 3
                params.memory_kb = 4096
                params.parallelism = 1
            
            if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0:
                if res.work_units_per_eval == expected_wu:
                    console.print_pass(f"{name} OK")
                    passed += 1
                else:
                    console.print_fail(f"{name} Failed. Expected {expected_wu}, got {res.work_units_per_eval}")
                    failed += 1
            else:
                console.print_fail(f"{name} Calculation Failed")
                failed += 1

        # 1. SHA-256 (Fast) - 0x0100, 64B -> 2000
        check(0x0100, 64, 2000, "SHA-256")

        # 2. Argon2id (MemHard) - 0x0200 -> 9830400
        check(0x0200, 0, 9830400, "Argon2id")

        # 3. SHA3-256 (Sponge) - 0x0300, 64B -> 1500
        check(0x0300, 64, 1500, "SHA3-256")

        # 4. MD5 (Legacy Alive) - 0x0400, 32B -> 500
        check(0x0400, 32, 500, "MD5")

        # 5. MD2 (Legacy Unsafe) - 0x0500, 16B -> 2400
        check(0x0500, 16, 2400, "MD2")

        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM Main: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM Main: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
