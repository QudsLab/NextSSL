"""KDF tests - HKDF, KDF-SHAKE256, TLS 1.3 HKDF."""

from .common import has_binaries, TEST_KEY_256, TEST_SALT_16


def run(log):
    from nextssl.kdf import KDFAlgorithm

    # ------------------------------------------------------------------
    log.section("KDFAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "HKDF_SHA256": 0, "HKDF_SHA3_256": 1, "HKDF_SHA3_512": 2,
        "KDF_SHAKE256": 10,
        "HKDF_EXPAND_LABEL": 20,
    }

    for name, val in expected.items():
        member = KDFAlgorithm[name]
        log.check(member.value == val, f"KDFAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(KDFAlgorithm) == len(expected),
              "KDFAlgorithm member count", got=len(KDFAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional KDF tests")
        return

    from nextssl.kdf import HKDF, KDF_SHAKE256, TLS13_HKDF

    log.section("HKDF constructor validation")

    for algo in [KDFAlgorithm.HKDF_SHA256, KDFAlgorithm.HKDF_SHA3_256, KDFAlgorithm.HKDF_SHA3_512]:
        h = HKDF(algo)
        log.check(h.algorithm == algo, f"HKDF({algo.name}).algorithm")

    log.section("KDF_SHAKE256 constructor")

    ks = KDF_SHAKE256()
    log.check(ks is not None, "KDF_SHAKE256 instantiates")

    log.section("TLS13_HKDF constructor")

    tls = TLS13_HKDF()
    log.check(tls is not None, "TLS13_HKDF instantiates")

    log.section("Functional: HKDF-SHA256 derive")

    h = HKDF(KDFAlgorithm.HKDF_SHA256)
    derived = h.derive(TEST_SALT_16, TEST_KEY_256, b"nextssl-test", 32)
    log.check(len(derived) == 32, "HKDF derive 32 bytes", size=len(derived))

    derived_other = h.derive(TEST_SALT_16, TEST_KEY_256, b"other-context", 32)
    log.check(derived != derived_other, "HKDF different info -> different output")

    log.section("Functional: KDF-SHAKE256 derive")

    ks = KDF_SHAKE256()
    out = ks.derive(TEST_KEY_256, b"nextssl-test", 48)
    log.check(len(out) == 48, "KDF-SHAKE256 derive 48 bytes", size=len(out))
