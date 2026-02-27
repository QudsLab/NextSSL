"""Test primitive_sponge_xof hash algorithms: 10 algorithms total.

SHA3-224, SHA3-256, SHA3-384, SHA3-512, Keccak-224, Keccak-256, Keccak-384, Keccak-512, SHAKE-128, SHAKE-256
"""

from ..common import TestLogger, VECTORS


def run():
    """Run all primitive_sponge_xof hash tests."""
    log = TestLogger("test_primitive_sponge_xof", "hash")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Primitive Sponge/XOF - Enum Validation")
    
    # All 10 algorithms (8 fixed-length + 2 XOF)
    fixed_algorithms = [
        (nextssl.HashAlgorithm.SHA3_224, 28, "SHA3-224"),
        (nextssl.HashAlgorithm.SHA3_256, 32, "SHA3-256"),
        (nextssl.HashAlgorithm.SHA3_384, 48, "SHA3-384"),
        (nextssl.HashAlgorithm.SHA3_512, 64, "SHA3-512"),
        (nextssl.HashAlgorithm.KECCAK_224, 28, "Keccak-224"),
        (nextssl.HashAlgorithm.KECCAK_256, 32, "Keccak-256"),
        (nextssl.HashAlgorithm.KECCAK_384, 48, "Keccak-384"),
        (nextssl.HashAlgorithm.KECCAK_512, 64, "Keccak-512"),
    ]
    
    xof_algorithms = [
        (nextssl.HashAlgorithm.SHAKE128, "SHAKE-128"),
        (nextssl.HashAlgorithm.SHAKE256, "SHAKE-256"),
    ]
    
    # Test 1: Fixed-length hashes
    for algo_enum, expected_size, name in fixed_algorithms:
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
    
    # Test 2: XOF (variable-length output)
    for algo_enum, name in xof_algorithms:
        try:
            if hasattr(nextssl, 'SHAKE'):
                # Use SHAKE class if available
                shake = nextssl.SHAKE(algo_enum)
                output = shake.digest(b"test", 64)  # Request 64 bytes
                if len(output) == 64:
                    log.pass_(f"{name} XOF", output_len=64, value=algo_enum.value)
                else:
                    log.fail(f"{name} XOF", expected=64, got=len(output))
            else:
                # Try Hash class with XOF
                hasher = nextssl.Hash(algo_enum)
                output = hasher.digest(b"test")
                log.pass_(f"{name} structure", size=len(output), value=algo_enum.value)
        except Exception as e:
            log.fail(f"{name} XOF", error=str(e))
    
    log.section("Primitive Sponge/XOF - Known Answer Tests")
    
    # Test 3: SHA3 KAT vectors
    test_data = [
        (b"abc", "SHA3_256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (b"", "SHA3_256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "SHA3_512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
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
    
    log.section("Primitive Sponge/XOF - Determinism")
    
    # Test 4: Same input → same output
    test_input = b"nextssl determinism test"
    
    for algo_enum, _, name in fixed_algorithms:
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
    
    for algo_enum, name in xof_algorithms:
        try:
            if hasattr(nextssl, 'SHAKE'):
                shake = nextssl.SHAKE(algo_enum)
                output1 = shake.digest(test_input, 64)
                output2 = shake.digest(test_input, 64)
                
                if output1 == output2:
                    log.pass_(f"{name} determinism", size=64)
                else:
                    log.fail(f"{name} determinism", reason="outputs differ")
            else:
                hasher = nextssl.Hash(algo_enum)
                digest1 = hasher.digest(test_input)
                digest2 = hasher.digest(test_input)
                
                if digest1 == digest2:
                    log.pass_(f"{name} determinism", size=len(digest1))
                else:
                    log.fail(f"{name} determinism", reason="outputs differ")
        except Exception as e:
            log.fail(f"{name} determinism", error=str(e))
    
    log.section("Primitive Sponge/XOF - Collision Resistance")
    
    # Test 5: Different inputs → different outputs
    data1 = b"nextssl"
    data2 = b"nextss1"
    
    for algo_enum, _, name in fixed_algorithms:
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
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
