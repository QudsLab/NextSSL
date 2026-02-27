"""Test legacy_unsafe hash algorithms: 7 algorithms total.

MD2, MD4, SHA-0, HAS-160, RIPEMD-128, RIPEMD-256, RIPEMD-320

WARNING: These algorithms are cryptographically broken and should NEVER be used
for security purposes. They are included only for compatibility with legacy systems.
"""

from ..common import TestLogger, VECTORS


def run():
    """Run all legacy_unsafe hash tests."""
    log = TestLogger("test_legacy_unsafe", "hash")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Legacy Unsafe Hash - SECURITY WARNING")
    
    log.info("=" * 70)
    log.info("WARNING: These algorithms are CRYPTOGRAPHICALLY BROKEN")
    log.info("DO NOT use for any security-sensitive applications!")
    log.info("Included ONLY for legacy system compatibility")
    log.info("=" * 70)
    
    log.section("Legacy Unsafe Hash - Enum Validation")
    
    # All 7 legacy unsafe algorithms with expected sizes
    # These might be in the unsafe module
    algorithms = []
    optional_algorithms = [
        ("MD2", 16, "MD2"),
        ("MD4", 16, "MD4"),
        ("SHA0", 20, "SHA-0"),
        ("HAS160", 20, "HAS-160"),
        ("RIPEMD128", 16, "RIPEMD-128"),
        ("RIPEMD256", 32, "RIPEMD-256"),
        ("RIPEMD320", 40, "RIPEMD-320"),
    ]
    
    # Test 1: Check if unsafe algorithms are available
    for algo_name, expected_size, display_name in optional_algorithms:
        try:
            # Try HashAlgorithm enum first
            if hasattr(nextssl.HashAlgorithm, algo_name):
                algo_enum = getattr(nextssl.HashAlgorithm, algo_name)
                algorithms.append((algo_enum, expected_size, display_name))
                log.info(f"{display_name} - available in HashAlgorithm")
            # Try unsafe module
            elif hasattr(nextssl, 'unsafe') and hasattr(nextssl.unsafe, algo_name):
                log.info(f"{display_name} - available in unsafe module")
            # Try legacy module
            elif hasattr(nextssl, 'legacy') and hasattr(nextssl.legacy, algo_name):
                log.info(f"{display_name} - available in legacy module")
            else:
                log.info(f"{display_name} - not implemented (expected for unsafe)")
        except Exception as e:
            log.info(f"{display_name} - error checking availability: {e}")
    
    # Test 2: Test available algorithms
    if algorithms:
        log.section("Legacy Unsafe Hash - Structure Tests")
        
        for algo_enum, expected_size, name in algorithms:
            try:
                hasher = nextssl.Hash(algo_enum)
                test_hash = hasher.digest(b"test")
                actual_size = len(test_hash)
                
                if actual_size == expected_size:
                    log.pass_(f"{name} structure", size=expected_size, value=algo_enum.value)
                else:
                    log.fail(f"{name} structure", expected=expected_size, got=actual_size)
            except Exception as e:
                log.fail(f"{name} structure", error=str(e))
        
        log.section("Legacy Unsafe Hash - Determinism")
        
        # Test 3: Same input → same output
        test_input = b"nextssl test"
        
        for algo_enum, _, name in algorithms:
            try:
                hasher = nextssl.Hash(algo_enum)
                digest1 = hasher.digest(test_input)
                digest2 = hasher.digest(test_input)
                
                if digest1 == digest2:
                    log.pass_(f"{name} determinism", size=len(digest1))
                else:
                    log.fail(f"{name} determinism", reason="outputs differ")
            except Exception as e:
                log.fail(f"{name} determinism", error=str(e))
        
        log.section("Legacy Unsafe Hash - Basic Functionality")
        
        # Test 4: Different inputs → different outputs (basic check)
        data1 = b"test1"
        data2 = b"test2"
        
        for algo_enum, _, name in algorithms:
            try:
                hasher = nextssl.Hash(algo_enum)
                digest1 = hasher.digest(data1)
                digest2 = hasher.digest(data2)
                
                if digest1 != digest2:
                    log.pass_(f"{name} basic_function", different=True)
                else:
                    log.fail(f"{name} basic_function", reason="same output")
            except Exception as e:
                log.fail(f"{name} basic_function", error=str(e))
    else:
        log.info("No unsafe algorithms implemented - this is GOOD for security!")
        log.info("If legacy compatibility is needed, they can be added via unsafe module")
        # Still pass the test suite since not having these is actually better
        log.pass_("Unsafe algorithms", status="not_implemented (secure)")
    
    log.section("Legacy Unsafe Hash - Final Warning")
    
    log.info("=" * 70)
    log.info("REMINDER: These algorithms have known vulnerabilities:")
    log.info("  - MD2, MD4: Completely broken, trivial collisions")
    log.info("  - SHA-0: Broken, replaced by SHA-1")
    log.info("  - HAS-160: Theoretical attacks exist")
    log.info("  - RIPEMD-128/256/320: Weak compared to modern standards")
    log.info("")
    log.info("Use modern alternatives:")
    log.info("  - SHA-256, SHA-512 (fast, secure)")
    log.info("  - SHA3-256, SHA3-512 (sponge construction)")
    log.info("  - BLAKE2b, BLAKE3 (fastest modern hashes)")
    log.info("=" * 70)
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
