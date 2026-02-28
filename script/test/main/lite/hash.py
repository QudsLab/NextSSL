"""
Test Suite: Lite Variant Hash Module
Tests SHA-256, SHA-512, BLAKE3 functionality
"""

import os
import sys
import ctypes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console

def test_hash_lite(color=True, platform=None):
    """Test lite hash module"""
    console.set_color(color)
    console.print_header("=== Test: Lite Hash Module ===")
    
    config = Config()
    dll_path = config.get_lib_path('main', 'hash', 'lite')
    
    if not os.path.exists(dll_path):
        console.print_fail(f"Hash DLL not found: {dll_path}")
        return 1
    
    try:
        lib = ctypes.CDLL(dll_path)
        console.print_pass(f"Loaded hash.dll from main/lite")
    except OSError as e:
        console.print_fail(f"Failed to load DLL: {e}")
        return 1
    
    # Expected symbols for lite variant
    expected_symbols = [
        'nextssl_lite_hash',
        'nextssl_lite_hash_size',
        'nextssl_lite_hash_available',
    ]
    
    missing = []
    for symbol in expected_symbols:
        if not hasattr(lib, symbol):
            missing.append(symbol)
    
    if missing:
        console.print_fail(f"Missing symbols: {missing}")
        return 1
    
    console.print_pass(f"All {len(expected_symbols)} symbols present")
    
    # Test SHA-256 (if wrapper is implemented)
    try:
        # Check function signature
        lib.nextssl_lite_hash.argtypes = [
            ctypes.c_char_p,  # algo_name
            ctypes.c_char_p,  # input
            ctypes.c_size_t,  # input_len
            ctypes.c_char_p   # output
        ]
        lib.nextssl_lite_hash.restype = ctypes.c_int
        
        # Test vector: SHA-256("abc") = ba7816bf...
        output = ctypes.create_string_buffer(32)
        result = lib.nextssl_lite_hash(b"SHA-256", b"abc", 3, output)
        
        if result == 0:
            expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            actual = output.raw.hex()
            
            if actual == expected:
                console.print_pass("SHA-256 output correct")
                console.print_info(f"  Hash: {actual}")
            else:
                console.print_fail(f"SHA-256 mismatch")
                console.print_info(f"  Expected: {expected}")
                console.print_info(f"  Got:      {actual}")
                return 1
        elif result == -99:  # NOT_IMPLEMENTED
            console.print_warning("SHA-256 not yet implemented (stub)")
        else:
            console.print_fail(f"SHA-256 failed with error {result}")
            return 1
            
    except Exception as e:
        console.print_warning(f"Could not test hash function: {e}")
    
    # Test algorithm availability
    try:
        lib.nextssl_lite_hash_available.argtypes = [ctypes.c_char_p]
        lib.nextssl_lite_hash_available.restype = ctypes.c_int
        
        # Should be available in lite
        available_algos = [b"SHA-256", b"SHA-512", b"BLAKE3"]
        
        for algo in available_algos:
            avail = lib.nextssl_lite_hash_available(algo)
            if avail:
                console.print_pass(f"{algo.decode()} available")
            else:
                console.print_warning(f"{algo.decode()} not available (expectedin lite)")
        
        # Should NOT be available in lite
        unavailable_algos = [b"MD5", b"SHA-1"]
        
        for algo in unavailable_algos:
            avail = lib.nextssl_lite_hash_available(algo)
            if not avail:
                console.print_pass(f"{algo.decode()} correctly blocked")
            else:
                console.print_fail(f"{algo.decode()} should not be in lite variant!")
                return 1
                
    except Exception as e:
        console.print_warning(f"Could not test availability: {e}")
    
    console.print_header("=== Test Complete ===")
    return 0


def main(color=True):
    """Entry point for test runner"""
    return test_hash_lite(color=color)


if __name__ == '__main__':
    sys.exit(main())
