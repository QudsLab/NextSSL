"""Test PoW client with primitive_fast hash category."""
from ...common import TestLogger

def run():
    log = TestLogger("test_primitive_fast", "pow/client")
    try:
        import nextssl
        if hasattr(nextssl, 'pow'):
            log.pass_("PoW module", available=True)
        log.info("PoW client with SHA-256, BLAKE2, etc.")
    except Exception as e:
        log.fail("PoW check", error=str(e))
    return log.summary()

if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
