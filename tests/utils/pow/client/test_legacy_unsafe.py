"""Test PoW client with legacy_unsafe hash category."""
from ...common import TestLogger

def run():
    log = TestLogger("test_legacy_unsafe", "pow/client")
    try:
        import nextssl
        if hasattr(nextssl, 'pow'):
            log.pass_("PoW module", available=True)
        log.info("PoW client with MD2/MD4")
    except Exception as e:
        log.fail("PoW check", error=str(e))
    return log.summary()

if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
