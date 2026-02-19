import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

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
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))
        DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'base', 'dhcm_primitive.dll')

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

        # 1. SHA-256 (Fast)
        params = DHCMParams(algorithm=0x0100, input_size=64)
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0 and res.work_units_per_eval == 2000:
            console.print_pass("SHA-256 OK")
            passed += 1
        else:
            console.print_fail("SHA-256 Failed")
            failed += 1

        # 2. Argon2id (MemHard)
        params = DHCMParams(algorithm=0x0200, difficulty_model=2, iterations=3, memory_kb=4096, parallelism=1)
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0 and res.work_units_per_eval == 9830400:
            console.print_pass("Argon2id OK")
            passed += 1
        else:
            console.print_fail("Argon2id Failed")
            failed += 1

        # 3. SHA3-256 (Sponge)
        params = DHCMParams(algorithm=0x0300, input_size=64)
        if lib.leyline_dhcm_calculate(ctypes.byref(params), ctypes.byref(res)) == 0 and res.work_units_per_eval == 1500:
            console.print_pass("SHA3-256 OK")
            passed += 1
        else:
            console.print_fail("SHA3-256 Failed")
            failed += 1

        print(f"\n{'='*50}")
        if failed == 0:
            console.print_pass(f"DHCM Base Primitive: {passed} passed")
            return 0
        else:
            console.print_fail(f"DHCM Base Primitive: {failed} failed")
            return 1

    except Exception as e:
        console.print_fail(f"Test crashed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
