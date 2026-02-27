"""Test primitive_fast hash algorithms: 7 algorithms total.

SHA-224, SHA-256, SHA-384, SHA-512, BLAKE2b, BLAKE2s, BLAKE3
"""

from ..common import TestLogger, VECTORS


def run():
    """Run all primitive_fast hash tests."""
    log = TestLogger("test_primitive_fast", "hash")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Primitive Fast Hash - Enum Validation")
    
    # All 7 algorithms with their expected sizes
    algorithms = [
        (nextssl.HashAlgorithm.SHA224, 28, "SHA-224"),
        (nextssl.HashAlgorithm.SHA256, 32, "SHA-256"),
        (nextssl.HashAlgorithm.SHA384, 48, "SHA-384"),
        (nextssl.HashAlgorithm.SHA512, 64, "SHA-512"),
        (nextssl.HashAlgorithm.BLAKE2B, 64, "BLAKE2b"),
        (nextssl.HashAlgorithm.BLAKE2S, 32, "BLAKE2s"),
        (nextssl.HashAlgorithm.BLAKE3, 32, "BLAKE3"),
    ]
    
    # Test 1: Enum existence and digest sizes
    for algo_enum, expected_size, name in algorithms:
        try:
            hasher = nextssl.Hash(algo_enum)
            if hasattr(hasher, 'digest_size'):
                actual_size = hasher.digest_size
            else:
                # Try to compute and check size
                test_hash = hasher.digest(b"test")
                actual_size = len(test_hash)
            
            if actual_size == expected_size:
                log.pass_(f"{name} structure", size=expected_size, value=algo_enum.value)
            else:
                log.fail(f"{name} structure", expected=expected_size, got=actual_size)
        except Exception as e:
            log.fail(f"{name} structure", error=str(e))
    
    log.section("Primitive Fast Hash - Known Answer Tests (NIST/RFC)")
    
    # Test 2: Verify against known test vectors
    test_data = [
        (b"abc", "SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"", "SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "SHA512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (b"", "SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        (b"abc", "SHA224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
        (b"abc", "SHA384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                          "8086072ba1e7cc2358baeca134c825a7"),
        (b"abc", "BLAKE2B", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
        (b"abc", "BLAKE2S", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
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
    
    log.section("Primitive Fast Hash - Determinism")
    
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
    
    log.section("Primitive Fast Hash - Collision Resistance")
    
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
                log.fail(f"{name} collision", reason="same output for different inputs")
        except Exception as e:
            log.fail(f"{name} collision", error=str(e))
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
