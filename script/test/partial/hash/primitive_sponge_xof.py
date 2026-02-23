import os
import sys
import ctypes

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console

def main(color=True):
    """Run all tests for primitive_sponge_xof.dll."""
    console.set_color(color)

    config = Config()
    DLL_PATH = config.get_lib_path('partial', 'primitive_sponge_xof', 'hash')

    console.print_info(f"Loading DLL: {DLL_PATH}")
    if not os.path.exists(DLL_PATH):
        console.print_fail(f"DLL not found: {DLL_PATH}")
        return 1
        
    try:
        lib = ctypes.CDLL(DLL_PATH)
    except OSError as e:
        console.print_fail(f"Failed to load DLL: {e}")
        return 1
    
    console.print_pass("DLL loaded successfully")

    # Define function signatures
    # void leyline_sha3_256(const uint8_t *data, size_t len, uint8_t digest[32]);
    lib.leyline_sha3_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_sha3_256.restype = None

    # void leyline_sha3_512(const uint8_t *data, size_t len, uint8_t digest[64]);
    lib.leyline_sha3_512.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_sha3_512.restype = None

    # void leyline_keccak_256(const uint8_t *data, size_t len, uint8_t digest[32]);
    lib.leyline_keccak_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_keccak_256.restype = None

    # void leyline_shake128(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
    lib.leyline_shake128.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.leyline_shake128.restype = None

    # void leyline_shake256(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
    lib.leyline_shake256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.leyline_shake256.restype = None

    passed = 0
    failed = 0

    def run_test(name, func, input_str, expected_hex, out_len=32, variable_out=False):
        nonlocal passed, failed
        data = input_str.encode('utf-8')
        digest = ctypes.create_string_buffer(out_len)
        
        try:
            if variable_out:
                func(data, len(data), digest, out_len)
            else:
                func(data, len(data), digest)
                
            actual_hex = digest.raw.hex()
            if actual_hex == expected_hex:
                console.print_pass(name)
                msg = f"       Hash ({out_len} bytes): {actual_hex}"
                console.log_to_file(msg)
                print(msg)
                passed += 1
            else:
                console.print_fail(name, input_val=input_str, expected=expected_hex, got=actual_hex)
                failed += 1
        except Exception as e:
            console.print_fail(f"{name} - Exception: {e}")
            failed += 1

    # SHA3-256
    run_test("SHA3-256 empty", lib.leyline_sha3_256, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 32)
    run_test("SHA3-256 'abc'", lib.leyline_sha3_256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32)

    # SHA3-512
    run_test("SHA3-512 'abc'", lib.leyline_sha3_512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", 64)

    # Keccak-256
    run_test("Keccak-256 empty", lib.leyline_keccak_256, "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", 32)

    # SHAKE-128 (32B)
    run_test("SHAKE-128 empty (32B)", lib.leyline_shake128, "", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", 32, True)

    # SHAKE-256 (32B)
    run_test("SHAKE-256 empty (32B)", lib.leyline_shake256, "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", 32, True)

    print(f"\n{'='*50}")
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
