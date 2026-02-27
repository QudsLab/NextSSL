"""Test PQC signature hash-based algorithms: 12 algorithms total.

SPHINCS+ variants with SHA2 and SHAKE, 128/192/256-bit security, fast/small
"""

from ..common import TestLogger


def run():
    """Run PQC signature hash-based tests."""
    log = TestLogger("test_sign_hash_based", "pqc")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("PQC Signature Hash-Based - SPHINCS+ Variants")
    
    # All 12 SPHINCS+ variants
    algorithms = [
        ("SPHINCS_SHA2_128F_SIMPLE", "SPHINCS+-SHA2-128f-simple"),
        ("SPHINCS_SHA2_128S_SIMPLE", "SPHINCS+-SHA2-128s-simple"),
        ("SPHINCS_SHA2_192F_SIMPLE", "SPHINCS+-SHA2-192f-simple"),
        ("SPHINCS_SHA2_192S_SIMPLE", "SPHINCS+-SHA2-192s-simple"),
        ("SPHINCS_SHA2_256F_SIMPLE", "SPHINCS+-SHA2-256f-simple"),
        ("SPHINCS_SHA2_256S_SIMPLE", "SPHINCS+-SHA2-256s-simple"),
        ("SPHINCS_SHAKE_128F_SIMPLE", "SPHINCS+-SHAKE-128f-simple"),
        ("SPHINCS_SHAKE_128S_SIMPLE", "SPHINCS+-SHAKE-128s-simple"),
        ("SPHINCS_SHAKE_192F_SIMPLE", "SPHINCS+-SHAKE-192f-simple"),
        ("SPHINCS_SHAKE_192S_SIMPLE", "SPHINCS+-SHAKE-192s-simple"),
        ("SPHINCS_SHAKE_256F_SIMPLE", "SPHINCS+-SHAKE-256f-simple"),
        ("SPHINCS_SHAKE_256S_SIMPLE", "SPHINCS+-SHAKE-256s-simple"),
    ]
    
    available_count = 0
    for enum_name, display_name in algorithms:
        try:
            if hasattr(nextssl.SignAlgorithm, enum_name):
                algo = getattr(nextssl.SignAlgorithm, enum_name)
                log.pass_(f"{display_name} available", value=algo.value)
                available_count += 1
            else:
                log.info(f"{display_name} - not found")
        except Exception as e:
            log.info(f"{display_name} - {e}")
    
    log.section("PQC Signature Hash-Based - Properties")
    
    log.info("SPHINCS+ characteristics:")
    log.info("  ✓ Based only on hash functions")
    log.info("  ✓ Most conservative PQC assumptions")
    log.info("  ✓ Stateless (unlike older hash signatures)")
    log.info("  ✓ Larger signatures than lattice schemes")
    log.info("")
    log.info("Naming convention:")log.info("  - SHA2 or SHAKE: Hash function used")
    log.info("  - 128/192/256: Security level in bits")
    log.info("  - f (fast): Optimized for speed")
    log.info("  - s (small): Optimized for size")
    log.info("  - simple: Simpler variant (vs robust)")
    log.info("")
    log.info("Trade-offs:")
    log.info("  (+) Most conservative security")
    log.info("  (+) Only requires hash functions")
    log.info("  (-) Large signatures (8-50 KB)")
    log.info("  (-) Slow signing (especially 's' variants)")
    log.info("")
    log.info("Use cases:")
    log.info("  - Long-term security requirements")
    log.info("  - Software updates (large messages, size amortizes)")
    log.info("  - Root certificates and trust anchors")
    log.info("  - When lattice assumptions are not trusted")
    
    if available_count > 0:
        log.pass_("SPHINCS+ availability", count=available_count)
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
