"""Test primitive_memory_hard hash algorithms: 3 algorithms total.

Argon2d, Argon2i, Argon2id
"""

from ..common import TestLogger, VECTORS


def run():
    """Run all primitive_memory_hard hash tests."""
    log = TestLogger("test_primitive_memory_hard", "hash")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Primitive Memory-Hard - Enum Validation")
    
    # All 3 Argon2 variants
    algorithms = [
        (nextssl.HashAlgorithm.ARGON2D, "Argon2d"),
        (nextssl.HashAlgorithm.ARGON2I, "Argon2i"),
        (nextssl.HashAlgorithm.ARGON2ID, "Argon2id"),
    ]
    
    # Test 1: Enum existence
    for algo_enum, name in algorithms:
        try:
            if hasattr(nextssl, 'Argon2'):
                # Use Argon2 class if available
                argon = nextssl.Argon2(algo_enum)
                log.pass_(f"{name} structure", value=algo_enum.value)
            else:
                # Try Hash class
                hasher = nextssl.Hash(algo_enum)
                log.pass_(f"{name} structure", value=algo_enum.value)
        except Exception as e:
            log.fail(f"{name} structure", error=str(e))
    
    log.section("Primitive Memory-Hard - Functional Tests")
    
    # Test 2: Hash computation with default parameters
    test_password = b"test_password_123"
    test_salt = b"test_salt_12345678"  # At least 8 bytes
    
    for algo_enum, name in algorithms:
        try:
            if hasattr(nextssl, 'Argon2'):
                argon = nextssl.Argon2(algo_enum)
                # Argon2 typically requires password, salt, and optional params
                result = argon.hash(test_password, test_salt)
                
                if result and len(result) > 0:
                    log.pass_(f"{name} hash", size=len(result))
                    log.data(f"{name}", result)
                else:
                    log.fail(f"{name} hash", reason="empty result")
            else:
                # Try with Hash class
                hasher = nextssl.Hash(algo_enum)
                result = hasher.digest(test_password)
                
                if result and len(result) > 0:
                    log.pass_(f"{name} hash", size=len(result))
                else:
                    log.fail(f"{name} hash", reason="empty result")
        except Exception as e:
            log.fail(f"{name} hash", error=str(e))
    
    log.section("Primitive Memory-Hard - Determinism")
    
    # Test 3: Same input + same salt → same output
    for algo_enum, name in algorithms:
        try:
            if hasattr(nextssl, 'Argon2'):
                argon = nextssl.Argon2(algo_enum)
                result1 = argon.hash(test_password, test_salt)
                result2 = argon.hash(test_password, test_salt)
                
                if result1 == result2:
                    log.pass_(f"{name} determinism", size=len(result1))
                else:
                    log.fail(f"{name} determinism", reason="outputs differ")
            else:
                hasher = nextssl.Hash(algo_enum)
                result1 = hasher.digest(test_password)
                result2 = hasher.digest(test_password)
                
                if result1 == result2:
                    log.pass_(f"{name} determinism", size=len(result1))
                else:
                    log.fail(f"{name} determinism", reason="outputs differ")
        except Exception as e:
            log.fail(f"{name} determinism", error=str(e))
    
    log.section("Primitive Memory-Hard - Salt Sensitivity")
    
    # Test 4: Different salt → different output
    test_salt2 = b"different_salt_12"
    
    for algo_enum, name in algorithms:
        try:
            if hasattr(nextssl, 'Argon2'):
                argon = nextssl.Argon2(algo_enum)
                result1 = argon.hash(test_password, test_salt)
                result2 = argon.hash(test_password, test_salt2)
                
                if result1 != result2:
                    log.pass_(f"{name} salt_sensitivity", different=True)
                else:
                    log.fail(f"{name} salt_sensitivity", reason="same output")
            else:
                log.info(f"{name} salt_sensitivity - skipped (needs Argon2 class)")
        except Exception as e:
            log.fail(f"{name} salt_sensitivity", error=str(e))
    
    log.section("Primitive Memory-Hard - Password Sensitivity")
    
    # Test 5: Different password → different output
    test_password2 = b"different_password"
    
    for algo_enum, name in algorithms:
        try:
            if hasattr(nextssl, 'Argon2'):
                argon = nextssl.Argon2(algo_enum)
                result1 = argon.hash(test_password, test_salt)
                result2 = argon.hash(test_password2, test_salt)
                
                if result1 != result2:
                    log.pass_(f"{name} password_sensitivity", different=True)
                else:
                    log.fail(f"{name} password_sensitivity", reason="same output")
            else:
                hasher = nextssl.Hash(algo_enum)
                result1 = hasher.digest(test_password)
                result2 = hasher.digest(test_password2)
                
                if result1 != result2:
                    log.pass_(f"{name} password_sensitivity", different=True)
                else:
                    log.fail(f"{name} password_sensitivity", reason="same output")
        except Exception as e:
            log.fail(f"{name} password_sensitivity", error=str(e))
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
