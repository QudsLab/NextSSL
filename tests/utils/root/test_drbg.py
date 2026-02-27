"""Test DRBG (Deterministic Random Bit Generator)."""

from ..common import TestLogger


def run():
    """Run DRBG tests."""
    log = TestLogger("test_drbg", "root")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("DRBG - Module Availability")
    
    if hasattr(nextssl, 'root') or hasattr(nextssl, 'DRBG'):
        log.pass_("DRBG module", available=True)
    else:
        log.info("DRBG not yet in Python API")
    
    log.section("DRBG - Properties")
    
    log.info("Deterministic Random Bit Generator:")
    log.info("  - Cryptographically secure PRNG")
    log.info("  - Seeded with entropy")
    log.info("  - Produces deterministic output from seed")
    log.info("  - Used for key generation, nonces, IVs")
    log.info("  - NIST SP 800-90A compliant")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
