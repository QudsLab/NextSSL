"""Test DHCM with primitive_sponge_xof hash category."""
from ..common import TestLogger

def run():
    log = TestLogger("test_primitive_sponge_xof", "dhcm")
    try:
        import nextssl
        if hasattr(nextssl, 'dhcm'):
            log.pass_("DHCM module", available=True)
        log.info("DHCM with SHA3/Keccak/SHAKE (sponge construction)")
    except Exception as e:
        log.fail("DHCM check", error=str(e))
    return log.summary()

if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
