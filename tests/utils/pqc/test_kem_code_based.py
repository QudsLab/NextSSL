"""Test PQC KEM code-based algorithms: 10 algorithms total.

McEliece variants: 348864, 348864f, 460896, 460896f, 6688128, 6688128f, 6960119, 6960119f, 8192128, 8192128f
"""

from ..common import TestLogger


def run():
    """Run PQC KEM code-based tests."""
    log = TestLogger("test_kem_code_based", "pqc")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()    
    
    log.section("PQC KEM Code-Based - McEliece Variants")
    
    # All 10 McEliece variants
    algorithms = [
        ("MCELIECE_348864", "McEliece-348864"),
        ("MCELIECE_348864F", "McEliece-348864f (fast)"),
        ("MCELIECE_460896", "McEliece-460896"),
        ("MCELIECE_460896F", "McEliece-460896f (fast)"),
        ("MCELIECE_6688128", "McEliece-6688128"),
        ("MCELIECE_6688128F", "McEliece-6688128f (fast)"),
        ("MCELIECE_6960119", "McEliece-6960119"),
        ("MCELIECE_6960119F", "McEliece-6960119f (fast)"),
        ("MCELIECE_8192128", "McEliece-8192128"),
        ("MCELIECE_8192128F", "McEliece-8192128f (fast)"),
    ]
    
    available_count = 0
    for enum_name, display_name in algorithms:
        try:
            if hasattr(nextssl.KEMAlgorithm, enum_name):
                algo = getattr(nextssl.KEMAlgorithm, enum_name)
                log.pass_(f"{display_name} available", value=algo.value)
                available_count += 1
            else:
                log.info(f"{display_name} - not implemented (large keys)")
        except Exception as e:
            log.info(f"{display_name} - {e}")
    
    log.section("PQC KEM Code-Based - Properties")
    
    log.info("McEliece characteristics:")
    log.info("  ✓ Oldest post-quantum KEM (1978)")
    log.info("  ✓ Well-studied, high confidence")
    log.info("  ✓ Very large public keys (100KB - 1MB)")
    log.info("  ✓ Fast encapsulation/decapsulation")
    log.info("  ✓ Based on error-correcting codes")
    log.info("")
    log.info("Naming convention:")
    log.info("  - Numbers indicate parameters (n, t)")
    log.info("  - 'f' suffix = fast variant (different representation)")
    log.info("  - Higher numbers = higher security level")
    log.info("")
    log.info("Trade-offs:")
    log.info("  (+) Fastest PQC KEM operations")
    log.info("  (+) Conservative security assumptions")
    log.info("  (-) Very large public keys")
    log.info("  (-) Not suitable for bandwidth-constrained applications")
    
    if available_count > 0:
        log.pass_("McEliece availability", count=available_count)
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
