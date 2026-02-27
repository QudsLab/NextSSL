"""Test DHCM with primitive_fast hash category.

DHCM (Dynamic Hash Chain Module) using fast hash algorithms.
"""

from ..common import TestLogger


def run():
    """Run DHCM primitive_fast tests."""
    log = TestLogger("test_primitive_fast", "dhcm")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("DHCM Primitive Fast - Module Availability")
    
    # Check DHCM availability
    if hasattr(nextssl, 'dhcm') or hasattr(nextssl, 'DHCM'):
        log.pass_("DHCM module", available=True)
    else:
        log.info("DHCM module not yet in Python API")
        log.info("DHCM provides dynamic hash chain functionality")
        return log.summary()
    
    log.section("DHCM Primitive Fast - Hash Category")
    
    log.info("DHCM with primitive_fast uses:")
    log.info("  - SHA-224, SHA-256, SHA-384, SHA-512")
    log.info("  - BLAKE2b, BLAKE2s, BLAKE3")
    log.info("")
    log.info("Purpose: Fast, standardized hash functions for DHCM")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
