import os
import sys
import ctypes

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console

def main(color=True):
    """Run all legacy tests for hash_legacy.dll (Base Tier)."""
    console.set_color(color)

    config = Config()
    DLL_PATH = config.get_lib_path('base', 'hash_legacy')

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

    symbols = ['nextssl_md5', 'nextssl_md2']
    
    missing = []
    for s in symbols:
        if not hasattr(lib, s):
            missing.append(s)
            
    if missing:
        console.print_fail(f"Missing symbols: {missing}")
        return 1
        
    passed = 0
    failed = 0
    
    # MD5 (Alive)
    lib.nextssl_md5.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.nextssl_md5.restype = ctypes.c_int
    digest = ctypes.create_string_buffer(16)
    lib.nextssl_md5(b"abc", 3, digest)
    if digest.raw.hex() == "900150983cd24fb0d6963f7d28e17f72":
        console.print_pass("MD5 (Alive category)")
        msg = f"       Hash (16 bytes): {digest.raw.hex()}"
        console.log_to_file(msg)
        print(msg)
        passed += 1
    else:
        console.print_fail("MD5")
        failed += 1

    # MD2 (Unsafe)
    lib.nextssl_md2.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.nextssl_md2.restype = ctypes.c_int
    digest = ctypes.create_string_buffer(16)
    lib.nextssl_md2(b"abc", 3, digest)
    if digest.raw.hex() == "da853b0d3f88d99b30283a69e6ded6bb":
        console.print_pass("MD2 (Unsafe category)")
        msg = f"       Hash (16 bytes): {digest.raw.hex()}"
        console.log_to_file(msg)
        print(msg)
        passed += 1
    else:
        console.print_fail("MD2")
        failed += 1

    print(f"\n{'='*50}")
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
