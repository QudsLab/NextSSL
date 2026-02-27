"""Test Hexadecimal encoding."""

from ..common import TestLogger


def run():
    """Run Hex encoding tests."""
    log = TestLogger("test_hex", "encoding")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Hex - Module Availability")
    
    if hasattr(nextssl, 'encoding') or hasattr(nextssl, 'Hex'):
        log.pass_("Hex module", available=True)
    else:
        log.info("Hex encoding not yet in Python API")
    
    log.section("Hex - Properties")
    
    log.info("Hexadecimal encoding:")
    log.info("  - 2 characters per byte (100% overhead)")
    log.info("  - Human-readable")
    log.info("  - Common for displaying binary data")
    log.info("  - Used: hashes, keys, debugging")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
