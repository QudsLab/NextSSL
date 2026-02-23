import os
import sys
import ctypes

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console

def main(color=True):
    """Run all tests for hash.dll (Main Tier)."""
    console.set_color(color)

    config = Config()
    DLL_PATH = config.get_lib_path('main', 'hash')

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

    symbols = ['leyline_sha256', 'leyline_md5']
    
    missing = []
    for s in symbols:
        if not hasattr(lib, s):
            missing.append(s)
            
    if missing:
        console.print_fail(f"Missing symbols: {missing}")
        return 1
        
    passed = 0
    failed = 0
    
    # Check SHA-256 (Primitive)
    lib.leyline_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_sha256.restype = None
    digest = ctypes.create_string_buffer(32)
    lib.leyline_sha256(b"abc", 3, digest)
    if digest.raw.hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        console.print_pass("SHA-256 (Primitive)")
        msg = f"       Hash (32 bytes): {digest.raw.hex()}"
        console.log_to_file(msg)
        print(msg)
        passed += 1
    else:
        console.print_fail("SHA-256")
        failed += 1

    # Check MD5 (Legacy)
    lib.leyline_md5.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.leyline_md5.restype = ctypes.c_int
    digest = ctypes.create_string_buffer(16)
    lib.leyline_md5(b"abc", 3, digest)
    if digest.raw.hex() == "900150983cd24fb0d6963f7d28e17f72":
        console.print_pass("MD5 (Legacy)")
        msg = f"       Hash (16 bytes): {digest.raw.hex()}"
        console.log_to_file(msg)
        print(msg)
        passed += 1
    else:
        console.print_fail("MD5")
        failed += 1

    print(f"\n{'='*50}")
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
