import os
import sys
import ctypes

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import console

def main(color=True):
    """Run all tests for primitive_fast.dll."""
    console.set_color(color)

    # 1. Resolve DLL path
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
    DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'hash', 'primitive_fast.dll')
    
    if sys.platform != 'win32':
        DLL_PATH = DLL_PATH.replace('.dll', '.so')

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

    # 2. Define function signatures
    # void leyline_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
    lib.leyline_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_sha256.restype = None

    # void leyline_sha512(const uint8_t *data, size_t len, uint8_t digest[64]);
    lib.leyline_sha512.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_sha512.restype = None

    # void leyline_blake3(const uint8_t *data, size_t len, uint8_t digest[32]);
    lib.leyline_blake3.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_blake3.restype = None
    
    # void leyline_blake2b(const uint8_t *data, size_t len, uint8_t *digest, size_t out_len);
    lib.leyline_blake2b.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.leyline_blake2b.restype = None

    # void leyline_blake2s(const uint8_t *data, size_t len, uint8_t *digest, size_t out_len);
    lib.leyline_blake2s.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    lib.leyline_blake2s.restype = None

    # SHA-224 (implied by TASK_HASH.md 9.4.1)
    # void leyline_sha224(const uint8_t *data, size_t len, uint8_t digest[28]);
    try:
        lib.leyline_sha224.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.leyline_sha224.restype = None
    except AttributeError:
        console.print_warn("leyline_sha224 not found")

    # SHA-384
    try:
        lib.leyline_sha384.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.leyline_sha384.restype = None
    except AttributeError:
        console.print_warn("leyline_sha384 not found")

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

    # SHA-256 Tests
    run_test("SHA-256 empty", lib.leyline_sha256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32)
    run_test("SHA-256 'abc'", lib.leyline_sha256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32)
    
    # SHA-512 Tests
    run_test("SHA-512 empty", lib.leyline_sha512, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 64)
    run_test("SHA-512 'abc'", lib.leyline_sha512, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64)

    # BLAKE3 Tests
    run_test("BLAKE3 empty", lib.leyline_blake3, "", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", 32)
    run_test("BLAKE3 'abc'", lib.leyline_blake3, "abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", 32)

    # BLAKE2b Tests (32 byte output)
    run_test("BLAKE2b empty (32B)", lib.leyline_blake2b, "", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", 32, variable_out=True)

    # BLAKE2s Tests (32 byte output)
    run_test("BLAKE2s empty (32B)", lib.leyline_blake2s, "", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 32, True)

    # SHA-224 Tests
    if hasattr(lib, 'leyline_sha224'):
        run_test("SHA-224 empty", lib.leyline_sha224, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", 28)
        run_test("SHA-224 'abc'", lib.leyline_sha224, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", 28)

    # SHA-384 Tests
    if hasattr(lib, 'leyline_sha384'):
        run_test("SHA-384 'abc'", lib.leyline_sha384, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", 48)

    print(f"\n{'='*50}")
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
