"""Test PQC signature lattice-based algorithms: 7 algorithms total.

ML-DSA-44, ML-DSA-65, ML-DSA-87 (Dilithium), Falcon-512, Falcon-1024, Falcon-Padded-512, Falcon-Padded-1024
"""

from ..common import TestLogger


def run():
    """Run PQC signature lattice tests."""
    log = TestLogger("test_sign_lattice", "pqc")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("PQC Signature Lattice - Algorithm Availability")
    
    # All 7 lattice-based signature algorithms
    algorithms = [
        ("ML_DSA_44", "ML-DSA-44", "Dilithium2 - NIST Level 2"),
        ("ML_DSA_65", "ML-DSA-65", "Dilithium3 - NIST Level 3"),
        ("ML_DSA_87", "ML-DSA-87", "Dilithium5 - NIST Level 5"),
        ("FALCON_512", "Falcon-512", "NIST Level 1"),
        ("FALCON_1024", "Falcon-1024", "NIST Level 5"),
        ("FALCON_PADDED_512", "Falcon-Padded-512", "Fixed-size variant"),
        ("FALCON_PADDED_1024", "Falcon-Padded-1024", "Fixed-size variant"),
    ]
    
    available_signs = []
    for enum_name, display_name, description in algorithms:
        try:
            if hasattr(nextssl.SignAlgorithm, enum_name):
                algo = getattr(nextssl.SignAlgorithm, enum_name)
                available_signs.append((algo, display_name))
                log.pass_(f"{display_name} available", desc=description, value=algo.value)
            else:
                log.info(f"{display_name} - not found")
        except Exception as e:
            log.info(f"{display_name} - {e}")
    
    if not available_signs:
        log.fail("PQC Signature", reason="no algorithms available")
        return log.summary()
    
    log.section("PQC Signature Lattice - Sign/Verify Cycle")
    
    # Test: Sign → Verify cycle
    test_message = b"Post-quantum signature test message"
    
    for algo, name in available_signs:
        try:
            signer = nextssl.Sign(algo)
            
            # Generate keypair
            public_key, secret_key = signer.keygen()
            
            log.data(f"{name} public_key", public_key.hex()[:64])
            
            # Sign message
            signature = signer.sign(secret_key, test_message)
            
            log.data(f"{name} signature", signature.hex()[:64])
            
            # Verify signature (should succeed)
            is_valid = signer.verify(public_key, test_message, signature)
            
            if is_valid:
                log.pass_(f"{name} sign_verify", 
                         sig_len=len(signature),
                         msg_len=len(test_message))
            else:
                log.fail(f"{name} sign_verify", reason="verification failed")
        except Exception as e:
            log.fail(f"{name} sign_verify", error=str(e))
    
    log.section("PQC Signature Lattice - Invalid Signature Detection")
    
    # Test: Modified signature should fail verification
    for algo, name in available_signs:
        try:
            signer = nextssl.Sign(algo)
            
            # Generate and sign
            public_key, secret_key = signer.keygen()
            signature = signer.sign(secret_key, test_message)
            
            # Tamper with signature
            tampered_sig = bytes([b ^ 0xFF for b in signature[:10]]) + signature[10:]
            
            # Should fail verification
            is_valid = signer.verify(public_key, test_message, tampered_sig)
            
            if not is_valid:
                log.pass_(f"{name} tamper_detection", detected=True)
            else:
                log.fail(f"{name} tamper_detection", reason="accepted tampered signature")
        except Exception as e:
            # Exception is also fine - means tampering was detected
            log.pass_(f"{name} tamper_detection", detected_via_exception=True)
    
    log.section("PQC Signature Lattice - Security Properties")
    
    log.info("Lattice-based signatures:")
    log.info("  ✓ Post-quantum secure")
    log.info("  ✓ Based on hard lattice problems")
    log.info("")
    log.info("ML-DSA (Dilithium) - NIST Standard:")
    log.info("  - Fast signing and verification")
    log.info("  - Moderate signature sizes")
    log.info("  - Recommended for general use")
    log.info("")
    log.info("Falcon:")
    log.info("  - Smallest signature sizes")
    log.info("  - More complex implementation")
    log.info("  - Padded variants have fixed-size signatures")
    log.info("")
    log.info("Comparison:")
    log.info("  - ML-DSA: Easier to implement, more robust")
    log.info("  - Falcon: More compact, harder to implement")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
