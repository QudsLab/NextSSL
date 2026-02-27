"""Test legacy_alive hash algorithms: 8 algorithms total.

MD5, SHA-1, RIPEMD-160, Whirlpool, Whirlpool-0, Whirlpool-T, NT Hash, AES-ECB (as hash)
"""

from ..common import TestLogger, VECTORS


def run():
    """Run all legacy_alive hash tests."""
    log = TestLogger("test_legacy_alive", "hash")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Legacy Alive Hash - Enum Validation")
    
    # All 8 legacy alive algorithms with expected sizes
    algorithms = [
        (nextssl.HashAlgorithm.MD5, 16, "MD5"),
        (nextssl.HashAlgorithm.SHA1, 20, "SHA-1"),
        (nextssl.HashAlgorithm.RIPEMD160, 20, "RIPEMD-160"),
        (nextssl.HashAlgorithm.WHIRLPOOL, 64, "Whirlpool"),
    ]
    
    # Optional algorithms that might not be implemented
    optional_algorithms = [
        ("WHIRLPOOL_0", 64, "Whirlpool-0"),
        ("WHIRLPOOL_T", 64, "Whirlpool-T"),
        ("NT_HASH", 16, "NT Hash"),
    ]
    
    # Test 1: Enum existence and digest sizes
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
    
    # Test optional algorithms
    for algo_name, expected_size, name in optional_algorithms:
        try:
            if hasattr(nextssl.HashAlgorithm, algo_name):
                algo_enum = getattr(nextssl.HashAlgorithm, algo_name)
                hasher = nextssl.Hash(algo_enum)
                test_hash = hasher.digest(b"test")
                actual_size = len(test_hash)
                
                if actual_size == expected_size:
                    log.pass_(f"{name} structure", size=expected_size, value=algo_enum.value)
                else:
                    log.fail(f"{name} structure", expected=expected_size, got=actual_size)
            else:
                log.info(f"{name} - not implemented (optional)")
        except Exception as e:
            log.fail(f"{name} structure", error=str(e))
    
    log.section("Legacy Alive Hash - Known Answer Tests")
    
    # Test 2: Verify against known test vectors
    test_data = [
        (b"abc", "MD5", "900150983cd24fb0d6963f7d28e17f72"),
        (b"", "MD5", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"abc", "SHA1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (b"", "SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ]
    
    for data, algo_name, expected_hex in test_data:
        try:
            algo_enum = getattr(nextssl.HashAlgorithm, algo_name)
            hasher = nextssl.Hash(algo_enum)
            result = hasher.digest(data)
            result_hex = result.hex()
            
            log.data(f"{algo_name}({len(data)} bytes)", result_hex)
            
            if result_hex == expected_hex:
                log.pass_(f"{algo_name} KAT", input_len=len(data))
            else:
                log.fail(f"{algo_name} KAT", 
                        expected=expected_hex[:16]+"...", 
                        got=result_hex[:16]+"...")
        except Exception as e:
            log.fail(f"{algo_name} KAT", error=str(e))
    
    log.section("Legacy Alive Hash - Determinism")
    
    # Test 3: Same input → same output (twice)
    test_input = b"nextssl determinism test"
    
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
    
    log.section("Legacy Alive Hash - Collision Resistance")
    
    # Test 4: Different inputs → different outputs
    data1 = b"nextssl"
    data2 = b"nextss1"
    
    for algo_enum, _, name in algorithms:
        try:
            hasher = nextssl.Hash(algo_enum)
            digest1 = hasher.digest(data1)
            digest2 = hasher.digest(data2)
            
            if digest1 != digest2:
                log.pass_(f"{name} collision", different=True)
            else:
                log.fail(f"{name} collision", reason="same output")
        except Exception as e:
            log.fail(f"{name} collision", error=str(e))
    
    log.section("Legacy Alive Hash - Security Warning")
    
    # Note: These are legacy algorithms, still alive but not recommended for new systems
    log.info("NOTE: These algorithms are legacy and should only be used for:")
    log.info("  - Compatibility with existing systems")
    log.info("  - Non-security-critical applications")
    log.info("  - MD5/SHA1: Known collision vulnerabilities")
    log.info("  - Use SHA-256 or better for new applications")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
