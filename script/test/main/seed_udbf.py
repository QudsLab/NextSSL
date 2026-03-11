"""script/test/main/seed_udbf.py — UDBF (User Defined Buffer Function) tests.

Tests UDBF deterministic byte feeder used for KAT (Known Answer Testing):
- Basic functionality: feed/read/wipe lifecycle
- Error conditions: exhaustion, invalid inputs
- Domain separation: identical seed + different labels → different outputs
- Determinism: identical seed + identical label → identical outputs
- Cross-algorithm validation: ALL 40 key-based algorithms × UDBF scenarios

UDBF provides HKDF-based domain-separated derivation for reproducible key
generation (testing only, not for production).
"""
import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from script.core                import Config, console
from script.test.core.result    import Results

# UDBF constants (from src/seed/udbf/udbf.h)
UDBF_OK            =  0
UDBF_ERR_NULL      = -1
UDBF_ERR_EXHAUSTED = -2
UDBF_ERR_DISABLED  = -3
UDBF_ERR_TOO_LARGE = -4

UDBF_MAX_FEED_LEN  = 1 << 20  # 1 MB
UDBF_MIN_FEED_LEN  = 32

# All 40 algorithms (from keygen.py)
# (display_name, algo_tag, pk_size, sk_size)
ALGORITHMS = [
    # ECC / symmetric
    ("Ed25519",            "ed25519",           32,      64),
    ("X25519",             "x25519",            32,      32),
    ("Ed448",              "ed448",             57,      57),
    ("X448",               "x448",              56,      56),
    ("Elligator2",         "elligator2",        32,      32),
    # ML-KEM
    ("ML-KEM-512",         "ml_kem_512",       800,    1632),
    ("ML-KEM-768",         "ml_kem_768",      1184,    2400),
    ("ML-KEM-1024",        "ml_kem_1024",     1568,    3168),
    # ML-DSA
    ("ML-DSA-44",          "ml_dsa_44",       1312,    2560),
    ("ML-DSA-65",          "ml_dsa_65",       1952,    4032),
    ("ML-DSA-87",          "ml_dsa_87",       2592,    4896),
    # Falcon
    ("Falcon-512",         "falcon_512",       897,    1281),
    ("Falcon-1024",        "falcon_1024",     1793,    2305),
    ("Falcon-Padded-512",  "falcon_padded_512",  897, 1281),
    ("Falcon-Padded-1024", "falcon_padded_1024", 1793, 2305),
    # SPHINCS+-SHA2
    ("SPHINCS+-SHA2-128f", "sphincs_sha2_128f", 32,    64),
    ("SPHINCS+-SHA2-128s", "sphincs_sha2_128s", 32,    64),
    ("SPHINCS+-SHA2-192f", "sphincs_sha2_192f", 48,    96),
    ("SPHINCS+-SHA2-192s", "sphincs_sha2_192s", 48,    96),
    ("SPHINCS+-SHA2-256f", "sphincs_sha2_256f", 64,   128),
    ("SPHINCS+-SHA2-256s", "sphincs_sha2_256s", 64,   128),
    # SPHINCS+-SHAKE
    ("SPHINCS+-SHAKE-128f", "sphincs_shake_128f", 32,  64),
    ("SPHINCS+-SHAKE-128s", "sphincs_shake_128s", 32,  64),
    ("SPHINCS+-SHAKE-192f", "sphincs_shake_192f", 48,  96),
    ("SPHINCS+-SHAKE-192s", "sphincs_shake_192s", 48,  96),
    ("SPHINCS+-SHAKE-256f", "sphincs_shake_256f", 64, 128),
    ("SPHINCS+-SHAKE-256s", "sphincs_shake_256s", 64, 128),
    # HQC
    ("HQC-128",            "hqc_128",         2249,    2305),
    ("HQC-192",            "hqc_192",         4522,    4586),
    ("HQC-256",            "hqc_256",         7245,    7317),
    # McEliece
    ("McEliece-348864",    "mceliece_348864",   261120,  6492),
    ("McEliece-348864f",   "mceliece_348864f",  261120,  6492),
    ("McEliece-460896",    "mceliece_460896",   524160, 13608),
    ("McEliece-460896f",   "mceliece_460896f",  524160, 13608),
    ("McEliece-6688128",   "mceliece_6688128", 1044992, 13932),
    ("McEliece-6688128f",  "mceliece_6688128f",1044992, 13932),
    ("McEliece-6960119",   "mceliece_6960119", 1047319, 13948),
    ("McEliece-6960119f",  "mceliece_6960119f",1047319, 13948),
    ("McEliece-8192128",   "mceliece_8192128", 1357824, 14120),
    ("McEliece-8192128f",  "mceliece_8192128f",1357824, 14120),
]


def test_udbf_basic_lifecycle(lib, r: Results):
    """Test basic UDBF feed/read/wipe cycle."""
    console.print_info("  Basic lifecycle tests")
    
    # Setup function pointers
    lib.udbf_feed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.udbf_feed.restype = ctypes.c_int
    lib.udbf_read.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.udbf_read.restype = ctypes.c_int
    lib.udbf_wipe.argtypes = []
    lib.udbf_wipe.restype = None
    lib.udbf_is_active.argtypes = []
    lib.udbf_is_active.restype = ctypes.c_int
    
    # Test 1: Feed valid seed
    seed = b'\x42' * 64
    ret = lib.udbf_feed(seed, len(seed))
    if ret == UDBF_OK and lib.udbf_is_active():
        r.ok("udbf_feed (valid seed)")
    else:
        r.fail("udbf_feed (valid seed)", reason=f"ret={ret} active={lib.udbf_is_active()}")
    
    # Test 2: Read bytes with label
    out = ctypes.create_string_buffer(32)
    ret = lib.udbf_read(b"test_label", out, 32)
    if ret == UDBF_OK and any(out.raw):
        r.ok("udbf_read (basic)")
    else:
        r.fail("udbf_read (basic)", reason=f"ret={ret} zero_output={not any(out.raw)}")
    
    # Test 3: Wipe
    lib.udbf_wipe()
    if not lib.udbf_is_active():
        r.ok("udbf_wipe")
    else:
        r.fail("udbf_wipe", reason="still active after wipe")


def test_udbf_error_conditions(lib, r: Results):
    """Test UDBF error handling."""
    console.print_info("  Error condition tests")
    
    lib.udbf_wipe()  # Ensure clean state
    
    # Test 1: Read when disabled
    out = ctypes.create_string_buffer(32)
    ret = lib.udbf_read(b"test", out, 32)
    if ret == UDBF_ERR_DISABLED:
        r.ok("udbf_read (disabled)")
    else:
        r.fail("udbf_read (disabled)", reason=f"expected UDBF_ERR_DISABLED, got {ret}")
    
    # Test 2: Feed NULL
    ret = lib.udbf_feed(None, 32)
    if ret == UDBF_ERR_NULL:
        r.ok("udbf_feed (NULL)")
    else:
        r.fail("udbf_feed (NULL)", reason=f"expected UDBF_ERR_NULL, got {ret}")
    
    # Test 3: Feed too short (< 32 bytes)
    seed = b'\x42' * 16
    ret = lib.udbf_feed(seed, len(seed))
    if ret == UDBF_ERR_NULL:
        r.ok("udbf_feed (too short)")
    else:
        r.fail("udbf_feed (too short)", reason=f"expected UDBF_ERR_NULL, got {ret}")
    
    # Test 4: Feed too large (> 1MB)
    # Don't allocate 2MB, just test with length parameter
    seed = b'\x42' * 1024
    ret = lib.udbf_feed(seed, UDBF_MAX_FEED_LEN + 1)
    if ret == UDBF_ERR_TOO_LARGE:
        r.ok("udbf_feed (too large)")
    else:
        r.fail("udbf_feed (too large)", reason=f"expected UDBF_ERR_TOO_LARGE, got {ret}")
    
    # Test 5: Read more than available (exhaustion)
    seed = b'\x42' * 64  # Feed 64 bytes
    lib.udbf_feed(seed, len(seed))
    out = ctypes.create_string_buffer(128)  # Try to read 128 bytes
    ret = lib.udbf_read(b"exhaustion_test", out, 128)
    if ret == UDBF_ERR_EXHAUSTED:
        r.ok("udbf_read (exhaustion)")
    else:
        r.fail("udbf_read (exhaustion)", reason=f"expected UDBF_ERR_EXHAUSTED, got {ret}")
    
    lib.udbf_wipe()


def test_udbf_domain_separation(lib, r: Results):
    """Test UDBF domain separation: same seed + different labels → different outputs."""
    console.print_info("  Domain separation tests")
    
    seed = b'\xAA' * 128
    lib.udbf_feed(seed, len(seed))
    
    # Generate three outputs with different labels
    out1 = ctypes.create_string_buffer(32)
    out2 = ctypes.create_string_buffer(32)
    out3 = ctypes.create_string_buffer(32)
    
    r1 = lib.udbf_read(b"label_1", out1, 32)
    
    # Reset and read again
    lib.udbf_feed(seed, len(seed))
    r2 = lib.udbf_read(b"label_2", out2, 32)
    
    # Reset and read with third label
    lib.udbf_feed(seed, len(seed))
    r3 = lib.udbf_read(b"label_3", out3, 32)
    
    if r1 == UDBF_OK and r2 == UDBF_OK and r3 == UDBF_OK:
        if out1.raw != out2.raw and out2.raw != out3.raw and out1.raw != out3.raw:
            r.ok("udbf domain separation (different labels)")
        else:
            r.fail("udbf domain separation (different labels)", 
                   reason="outputs not unique")
    else:
        r.fail("udbf domain separation (different labels)", 
               reason=f"udbf_read failed: {r1}, {r2}, {r3}")
    
    lib.udbf_wipe()


def test_udbf_determinism(lib, r: Results):
    """Test UDBF determinism: same seed + same label → same output."""
    console.print_info("  Determinism tests")
    
    seed = b'\xBB' * 128
    label = b"determinism_test"
    
    # First generation
    lib.udbf_feed(seed, len(seed))
    out1 = ctypes.create_string_buffer(64)
    r1 = lib.udbf_read(label, out1, 64)
    
    # Second generation (reset state)
    lib.udbf_feed(seed, len(seed))
    out2 = ctypes.create_string_buffer(64)
    r2 = lib.udbf_read(label, out2, 64)
    
    if r1 == UDBF_OK and r2 == UDBF_OK:
        if out1.raw == out2.raw:
            r.ok("udbf determinism (identical inputs)")
        else:
            r.fail("udbf determinism (identical inputs)", 
                   reason="outputs differ")
    else:
        r.fail("udbf determinism (identical inputs)", 
               reason=f"udbf_read failed: {r1}, {r2}")
    
    lib.udbf_wipe()


def test_udbf_collision_resistance(lib, r: Results):
    """Test UDBF collision resistance: different seeds → different outputs."""
    console.print_info("  Collision resistance tests")
    
    label = b"collision_test"
    
    # Generate with seed1
    seed1 = b'\xCC' * 128
    lib.udbf_feed(seed1, len(seed1))
    out1 = ctypes.create_string_buffer(32)
    r1 = lib.udbf_read(label, out1, 32)
    
    # Generate with seed2
    seed2 = b'\xDD' * 128
    lib.udbf_feed(seed2, len(seed2))
    out2 = ctypes.create_string_buffer(32)
    r2 = lib.udbf_read(label, out2, 32)
    
    if r1 == UDBF_OK and r2 == UDBF_OK:
        if out1.raw != out2.raw:
            r.ok("udbf collision resistance (different seeds)")
        else:
            r.fail("udbf collision resistance (different seeds)", 
                   reason="outputs identical")
    else:
        r.fail("udbf collision resistance (different seeds)", 
               reason=f"udbf_read failed: {r1}, {r2}")
    
    lib.udbf_wipe()


def test_udbf_bit_distribution(lib, r: Results):
    """Test UDBF bit distribution (basic statistical test)."""
    console.print_info("  Bit distribution tests")
    
    seed = b'\xEE' * 256
    lib.udbf_feed(seed, len(seed))
    
    # Generate 256 bytes
    out = ctypes.create_string_buffer(256)
    ret = lib.udbf_read(b"bit_distribution", out, 256)
    
    if ret == UDBF_OK:
        # Count 1-bits
        ones = sum(bin(byte).count('1') for byte in out.raw)
        total_bits = 256 * 8
        ratio = ones / total_bits
        
        # Should be roughly 50% (allow 40%-60% range for basic test)
        if 0.4 <= ratio <= 0.6:
            r.ok(f"udbf bit distribution (ratio={ratio:.3f})")
        else:
            r.fail(f"udbf bit distribution (ratio={ratio:.3f})", 
                   reason=f"bit ratio outside [0.4, 0.6]")
    else:
        r.fail("udbf bit distribution", reason=f"udbf_read failed: {ret}")
    
    lib.udbf_wipe()


def test_udbf_cross_algorithm_validation(lib, r: Results):
    """Test UDBF with ALL 40 key-based algorithms.
    
    For each algorithm, verify:
    - UDBF-derived seed can generate valid keys
    - Determinism: same UDBF state → same keys
    - Uniqueness: different UDBF labels → different keys
    """
    console.print_info("  Cross-algorithm validation (40 algorithms × 6 scenarios)")
    
    # Load pqc.dll for PQC algorithms
    config = Config()
    bin_dir = os.path.dirname(os.path.abspath(config.get_lib_path('main', 'core')))
    if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
        os.add_dll_directory(bin_dir)
    pqc_path = config.get_lib_path('main', 'pqc')
    if os.path.exists(pqc_path):
        ctypes.CDLL(pqc_path)
    
    master_seed = b'\xFF' * 512  # Large seed for all algorithms
    
    for display_name, algo_tag, pk_size, sk_size in ALGORITHMS:
        # Check if keygen function exists
        fn_name = f"keygen_{algo_tag}_drbg"
        try:
            fn = getattr(lib, fn_name)
        except AttributeError:
            r.fail(f"UDBF × {display_name}", reason=f"{fn_name} not found")
            continue
        
        # Setup function signature (drbg mode: seed, seed_len, label, pk, sk)
        fn.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
        fn.restype = ctypes.c_int
        
        # Scenario 1: Basic generation with UDBF-derived seed
        lib.udbf_feed(master_seed, len(master_seed))
        seed1 = ctypes.create_string_buffer(64)
        if lib.udbf_read(f"seed_{algo_tag}_1".encode(), seed1, 64) != UDBF_OK:
            r.fail(f"UDBF × {display_name} (scenario 1)", reason="udbf_read failed")
            lib.udbf_wipe()
            continue
        
        pk1 = ctypes.create_string_buffer(pk_size)
        sk1 = ctypes.create_string_buffer(sk_size)
        ret1 = fn(seed1, 64, b"test", pk1, sk1)
        
        if ret1 == 0 and any(pk1.raw) and any(sk1.raw):
            r.ok(f"UDBF × {display_name} (basic generation)")
        else:
            r.fail(f"UDBF × {display_name} (basic generation)", 
                   reason=f"ret={ret1}, zero_keys={not any(pk1.raw)}")
        
        # Scenario 2: Determinism - same UDBF output → same keys
        lib.udbf_feed(master_seed, len(master_seed))
        seed2 = ctypes.create_string_buffer(64)
        lib.udbf_read(f"seed_{algo_tag}_1".encode(), seed2, 64)  # Same label as scenario 1
        
        pk2 = ctypes.create_string_buffer(pk_size)
        sk2 = ctypes.create_string_buffer(sk_size)
        ret2 = fn(seed2, 64, b"test", pk2, sk2)
        
        if ret2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
            r.ok(f"UDBF × {display_name} (determinism)")
        else:
            r.fail(f"UDBF × {display_name} (determinism)", 
                   reason=f"keys differ: pk_match={pk1.raw==pk2.raw}")
        
        # Scenario 3: Uniqueness - different UDBF label → different keys
        lib.udbf_feed(master_seed, len(master_seed))
        seed3 = ctypes.create_string_buffer(64)
        lib.udbf_read(f"seed_{algo_tag}_2".encode(), seed3, 64)  # Different label
        
        pk3 = ctypes.create_string_buffer(pk_size)
        sk3 = ctypes.create_string_buffer(sk_size)
        ret3 = fn(seed3, 64, b"test", pk3, sk3)
        
        if ret3 == 0 and pk1.raw != pk3.raw:
            r.ok(f"UDBF × {display_name} (uniqueness)")
        else:
            r.fail(f"UDBF × {display_name} (uniqueness)",
                   reason=f"keys identical when should differ",
                   debug_data={"seed1": seed1.raw, "seed3": seed3.raw, "pk1": pk1.raw, "pk3": pk3.raw} if console.DEBUG_MODE else None)
        
        # Scenario 4: Different keygen label → different keys (domain separation at keygen level)
        lib.udbf_feed(master_seed, len(master_seed))
        seed4 = ctypes.create_string_buffer(64)
        lib.udbf_read(f"seed_{algo_tag}_1".encode(), seed4, 64)  # Same UDBF label
        
        pk4 = ctypes.create_string_buffer(pk_size)
        sk4 = ctypes.create_string_buffer(sk_size)
        ret4 = fn(seed4, 64, b"different_label", pk4, sk4)  # Different keygen label
        
        if ret4 == 0 and pk1.raw != pk4.raw:
            r.ok(f"UDBF × {display_name} (keygen label separation)")
        else:
            r.fail(f"UDBF × {display_name} (keygen label separation)",
                   reason=f"keys identical when keygen labels differ",
                   debug_data={"seed4": seed4.raw, "pk1": pk1.raw, "pk4": pk4.raw} if console.DEBUG_MODE else None)
        
        # Scenario 5: Non-zero output validation
        if any(pk1.raw) and any(sk1.raw) and any(pk3.raw) and any(sk3.raw):
            r.ok(f"UDBF × {display_name} (non-zero keys)")
        else:
            r.fail(f"UDBF × {display_name} (non-zero keys)", 
                   reason="some keys are all zeros")
        
        # Scenario 6: Seed variation → key variation
        lib.udbf_feed(b'\xAA' * 512, 512)  # Different master seed
        seed5 = ctypes.create_string_buffer(64)
        lib.udbf_read(f"seed_{algo_tag}_1".encode(), seed5, 64)
        
        pk5 = ctypes.create_string_buffer(pk_size)
        sk5 = ctypes.create_string_buffer(sk_size)
        ret5 = fn(seed5, 64, b"test", pk5, sk5)
        
        if ret5 == 0 and pk1.raw != pk5.raw:
            r.ok(f"UDBF × {display_name} (seed variation)")
        else:
            r.fail(f"UDBF × {display_name} (seed variation)",
                   reason=f"keys identical with different master seed",
                   debug_data={"seed1": seed1.raw, "seed5": seed5.raw, "pk1": pk1.raw, "pk5": pk5.raw} if console.DEBUG_MODE else None)
        
        lib.udbf_wipe()


def main() -> int:
    config = Config()
    dll_path = config.get_lib_path('main', 'core')
    console.print_info(f"Loading: {dll_path}")
    
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1
    
    console.print_pass("DLL loaded")
    
    r = Results('test/main/seed_udbf')
    
    console.print_info("UDBF Unit Tests")
    test_udbf_basic_lifecycle(lib, r)
    test_udbf_error_conditions(lib, r)
    test_udbf_domain_separation(lib, r)
    test_udbf_determinism(lib, r)
    test_udbf_collision_resistance(lib, r)
    test_udbf_bit_distribution(lib, r)
    test_udbf_cross_algorithm_validation(lib, r)
    
    return r.summary()


if __name__ == '__main__':
    sys.exit(main())
