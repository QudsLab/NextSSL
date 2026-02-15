import os
import sys
import ctypes

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import console

class LeylineArgon2Params(ctypes.Structure):
    _fields_ = [
        ("t_cost", ctypes.c_uint32),
        ("m_cost_kb", ctypes.c_uint32),
        ("parallelism", ctypes.c_uint32),
    ]

def main(color=True):
    """Run all tests for primitive_memory_hard.dll."""
    console.set_color(color)

    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../'))
    DLL_PATH = os.path.join(PROJECT_ROOT, 'bin', 'partial', 'hash', 'primitive_memory_hard.dll')
    
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

    # Define function signatures
    # int leyline_argon2id(const uint8_t *pwd, size_t pwd_len, 
    #                      const uint8_t *salt, size_t salt_len,
    #                      const LeylineArgon2Params *params,
    #                      uint8_t *out, size_t out_len);
    
    sig = [ctypes.c_char_p, ctypes.c_size_t, 
           ctypes.c_char_p, ctypes.c_size_t, 
           ctypes.POINTER(LeylineArgon2Params), 
           ctypes.c_char_p, ctypes.c_size_t]
    
    lib.leyline_argon2id.argtypes = sig
    lib.leyline_argon2id.restype = ctypes.c_int
    
    lib.leyline_argon2i.argtypes = sig
    lib.leyline_argon2i.restype = ctypes.c_int
    
    lib.leyline_argon2d.argtypes = sig
    lib.leyline_argon2d.restype = ctypes.c_int

    passed = 0
    failed = 0

    def run_test(name, func, pwd, salt, t_cost, m_cost, p, out_len=32, expected_hex=None):
        nonlocal passed, failed
        
        params = LeylineArgon2Params()
        params.t_cost = t_cost
        params.m_cost_kb = m_cost
        params.parallelism = p
        
        pwd_bytes = pwd.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        out_buf = ctypes.create_string_buffer(out_len)
        
        try:
            res = func(pwd_bytes, len(pwd_bytes), 
                       salt_bytes, len(salt_bytes), 
                       ctypes.byref(params), 
                       out_buf, out_len)
            
            if res == 0: # ARGON2_OK is usually 0
                actual_hex = out_buf.raw.hex()
                
                if expected_hex:
                    if actual_hex == expected_hex:
                        console.print_pass(name)
                        msg = f"       Hash ({out_len} bytes): {actual_hex}"
                        console.log_to_file(msg)
                        passed += 1
                    else:
                        console.print_fail(name, input_val=f"out_len={out_len}", expected=expected_hex, got=actual_hex)
                        failed += 1
                else:
                    console.print_pass(name)
                    msg = f"       Hash ({out_len} bytes): {actual_hex}"
                    console.log_to_file(msg)
                    print(msg)
                    passed += 1
            else:
                console.print_fail(f"{name} - Returned {res}")
                failed += 1
        except Exception as e:
            console.print_fail(f"{name} - Exception: {e}")
            failed += 1

    # Argon2id Test
    # Test vector: RFC 9106 is complicated, we'll just check it runs without crashing
    # We use small parameters for speed in unit tests, but print the output for manual verification
    run_test("Argon2id (t=2, m=16, p=1, out=32)", lib.leyline_argon2id, "password", "somesalt", 2, 16, 1, 32, "058202c0723cd88c24408ccac1cbf828dee63bcf3843a150ea364a1e0b4e1ff8")
    run_test("Argon2id (t=2, m=16, p=1, out=64)", lib.leyline_argon2id, "password", "somesalt", 2, 16, 1, 64, "6d476f01ce2ad5c1b6586c0fd4a1c32f58fae9efee8678db81dca8ab730ad3121acd886ff3b187a889689cf3c7d58ed7ff3f0ab90db8df7eafd92cdea792db67")
    run_test("Argon2id (t=2, m=16, p=1, out=16)", lib.leyline_argon2id, "password", "somesalt", 2, 16, 1, 16, "f7b15c4365eb5d1181bb5eb520336485")
    
    # Argon2i Test
    run_test("Argon2i (t=2, m=16, p=1, out=32)", lib.leyline_argon2i, "password", "somesalt", 2, 16, 1, 32, "03df1d13e10203bcc663405e31ab1687939730c9152459bca28fd10c23e38f50")

    # Argon2d Test
    run_test("Argon2d (t=2, m=16, p=1, out=32)", lib.leyline_argon2d, "password", "somesalt", 2, 16, 1, 32, "e742c05880c44c4df5fe79937be77897a6e41ca758affc42301f1e4040e35bd2")

    print(f"\n{'='*50}")
    console.print_info(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
