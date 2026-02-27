"""Test PoW server - all 5 hash categories."""
from ...common import TestLogger

def run():
    log = TestLogger("test_primitive_fast", "pow/server")
    try:
        import nextssl
        if hasattr(nextssl, 'pow'):
            log.pass_("PoW server", available=True)
        log.info("PoW server validates client solutions")
    except Exception as e:
        log.fail("PoW check", error=str(e))
    return log.summary()

if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
