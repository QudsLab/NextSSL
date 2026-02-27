"""Test DHCM with legacy_alive hash category."""
from ..common import TestLogger

def run():
    log = TestLogger("test_legacy_alive", "dhcm")
    try:
        import nextssl
        if hasattr(nextssl, 'dhcm'):
            log.pass_("DHCM module", available=True)
        log.info("DHCM with MD5/SHA-1 (legacy compatibility)")
    except Exception as e:
        log.fail("DHCM check", error=str(e))
    return log.summary()

if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
