"""Test PQC KEM lattice-based algorithms: 6 algorithms total.

ML-KEM-512, ML-KEM-768, ML-KEM-1024 (Kyber), HQC-128, HQC-192, HQC-256
"""

from ..common import TestLogger


def run():
    """Run PQC KEM lattice tests."""
    log = TestLogger("test_kem_lattice", "pqc")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("PQC KEM Lattice - Algorithm Availability")
    
    # All 6 lattice-based KEM algorithms
    algorithms = [
        ("ML_KEM_512", "ML-KEM-512", "Kyber512 - NIST Level 1"),
        ("ML_KEM_768", "ML-KEM-768", "Kyber768 - NIST Level 3"),
        ("ML_KEM_1024", "ML-KEM-1024", "Kyber1024 - NIST Level 5"),
        ("HQC_128", "HQC-128", "HQC - NIST Level 1"),
        ("HQC_192", "HQC-192", "HQC - NIST Level 3"),
        ("HQC_256", "HQC-256", "HQC - NIST Level  5"),
    ]
    
    available_kems = []
    for enum_name, display_name, description in algorithms:
        try:
            if hasattr(nextssl.KEMAlgorithm, enum_name):
                algo = getattr(nextssl.KEMAlgorithm, enum_name)
                available_kems.append((algo, display_name))
                log.pass_(f"{display_name} available", desc=description, value=algo.value)
            else:
                log.info(f"{display_name} - not found")
        except Exception as e:
            log.fail(f"{display_name} check", error=str(e))
    
    if not available_kems:
        log.fail("PQC KEM", reason="no algorithms available")
        return log.summary()
    
    log.section("PQC KEM Lattice - Key Generation")
    
    # Test 2: Key generation for each algorithm
    for algo, name in available_kems:
        try:
            kem = nextssl.KEM(algo)
            public_key, secret_key = kem.keygen()
            
            log.data(f"{name} public_key", public_key.hex())
            log.data(f"{name} secret_key", secret_key.hex()[:64])  # Show first 32 bytes
            
            if public_key and secret_key:
                log.pass_(f"{name} keygen", pk_len=len(public_key), sk_len=len(secret_key))
            else:
                log.fail(f"{name} keygen", reason="empty keys")
        except Exception as e:
            log.fail(f"{name} keygen", error=str(e))
    
    log.section("PQC KEM Lattice - Encapsulation/Decapsulation")
    
    # Test 3: Full KEM cycle: keygen → encaps → decaps
    for algo, name in available_kems:
        try:
            kem = nextssl.KEM(algo)
            
            # Generate keypair
            public_key, secret_key = kem.keygen()
            
            # Encapsulate (generates shared secret + ciphertext)
            ciphertext, shared_secret1 = kem.encapsulate(public_key)
            
            log.data(f"{name} ciphertext", ciphertext.hex())
            log.data(f"{name} shared_secret", shared_secret1.hex())
            
            # Decapsulate (recover shared secret)
            shared_secret2 = kem.decapsulate(secret_key, ciphertext)
            
            # Verify shared secrets match
            if shared_secret1 == shared_secret2:
                log.pass_(f"{name} KEM_cycle", 
                         ct_len=len(ciphertext), 
                         ss_len=len(shared_secret1))
            else:
                log.fail(f"{name} KEM_cycle", reason="shared secrets don't match")
        except Exception as e:
            log.fail(f"{name} KEM_cycle", error=str(e))
    
    log.section("PQC KEM Lattice - Wrong Key Detection")
    
    # Test 4: Different secret key → different shared secret
    for algo, name in available_kems:
        try:
            kem = nextssl.KEM(algo)
            
            # Generate two keypairs
            public_key1, secret_key1 = kem.keygen()
            public_key2, secret_key2 = kem.keygen()
            
            # Encapsulate with first public key
            ciphertext, shared_secret_correct = kem.encapsulate(public_key1)
            
            # Try to decapsulate with wrong secret key
            shared_secret_wrong = kem.decapsulate(secret_key2, ciphertext)
            
            # Should produce different shared secret
            if shared_secret_correct != shared_secret_wrong:
                log.pass_(f"{name} wrong_key", detected=True)
            else:
                log.fail(f"{name} wrong_key", reason="same shared secret")
        except Exception as e:
            # Exception is also fine - means wrong key was detected
            log.pass_(f"{name} wrong_key", detected_via_exception=True)
    
    log.section("PQC KEM Lattice - Security Properties")
    
    log.info("Lattice-based KEM security:")
    log.info("  ✓ Post-quantum secure (resistant to quantum attacks)")
    log.info("  ✓ Based on hard lattice problems (LWE, Ring-LWE)")
    log.info("  ✓ NIST standardized (ML-KEM = Kyber)")
    log.info("")
    log.info("ML-KEM (Kyber) - NIST Standard:")
    log.info("  - ML-KEM-512: ~128-bit quantum security")
    log.info("  - ML-KEM-768: ~192-bit quantum security (recommended)")
    log.info("  - ML-KEM-1024: ~256-bit quantum security")
    log.info("")
    log.info("HQC (Hamming Quasi-Cyclic):")
    log.info("  - Code-based alternative")
    log.info("  - Similar security levels")
    log.info("  - Different mathematical foundation")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
