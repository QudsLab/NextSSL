"""Root module tests - DRBG + UDBF."""

from .common import has_binaries, TEST_DRBG_SEED


def run(log):
    from nextssl.root import DRBG, UDBF, seed_drbg, reseed_drbg, set_udbf, clear_udbf, get_drbg, get_udbf

    # ------------------------------------------------------------------
    log.section("Class methods exist (static check)")
    # ------------------------------------------------------------------

    log.check(hasattr(DRBG, 'seed'), "DRBG has seed method")
    log.check(hasattr(DRBG, 'reseed'), "DRBG has reseed method")
    log.check(hasattr(UDBF, 'set'), "UDBF has set method")
    log.check(hasattr(UDBF, 'clear'), "UDBF has clear method")

    # ------------------------------------------------------------------
    log.section("Convenience functions exist")
    # ------------------------------------------------------------------

    log.check(callable(seed_drbg), "seed_drbg is callable")
    log.check(callable(reseed_drbg), "reseed_drbg is callable")
    log.check(callable(set_udbf), "set_udbf is callable")
    log.check(callable(clear_udbf), "clear_udbf is callable")
    log.check(callable(get_drbg), "get_drbg is callable")
    log.check(callable(get_udbf), "get_udbf is callable")

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping functional root tests")
        return

    log.section("Functional: DRBG seed")

    drbg = DRBG()
    drbg.seed(TEST_DRBG_SEED)
    log.check(True, "DRBG.seed(48 bytes) succeeds")

    log.section("Functional: DRBG reseed")

    drbg.reseed(TEST_DRBG_SEED)
    log.check(True, "DRBG.reseed(48 bytes) succeeds")

    log.section("Functional: UDBF set and clear")

    udbf = UDBF()
    udbf.set(b"\xaa" * 256)
    log.check(True, "UDBF.set(256 bytes) succeeds")
    udbf.clear()
    log.check(True, "UDBF.clear() succeeds")

    log.section("Functional: DRBG determinism")

    drbg.seed(TEST_DRBG_SEED)
    from nextssl.pqc.kem_complete import KEM, KEMAlgorithm
    k = KEM(KEMAlgorithm.ML_KEM_512)
    pk1, sk1 = k.keypair()

    drbg.seed(TEST_DRBG_SEED)
    pk2, sk2 = k.keypair()

    log.check(pk1 == pk2, "DRBG determinism: same seed -> same pk")
    log.check(sk1 == sk2, "DRBG determinism: same seed -> same sk")
