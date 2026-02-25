"""MAC tests - 11 algorithms."""

from .common import has_binaries, TEST_KEY_256, TEST_DATA_SHORT, TEST_SIPHASH_KEY


def run(log):
    from nextssl.primitives.mac_complete import MACAlgorithm, MAC, SipHash

    # ------------------------------------------------------------------
    log.section("MACAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "CMAC_AES": 0, "POLY1305": 10, "AES_POLY1305": 11,
        "SIPHASH_2_4": 20, "SIPHASH_4_8": 21,
        "HMAC_SHA256": 100, "HMAC_SHA512": 101,
        "HMAC_SHA3_256": 102, "HMAC_SHA3_512": 103,
        "HMAC_SHA1": 104, "HMAC_MD5": 105,
    }

    for name, val in expected.items():
        member = MACAlgorithm[name]
        log.check(member.value == val, f"MACAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(MACAlgorithm) == len(expected),
              "MACAlgorithm member count", got=len(MACAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("MAC.TAG_SIZES coverage (static)")
    # ------------------------------------------------------------------

    expected_tag_sizes = {
        "CMAC_AES": 16, "POLY1305": 16, "AES_POLY1305": 16,
        "SIPHASH_2_4": 8, "SIPHASH_4_8": 8,
        "HMAC_SHA256": 32, "HMAC_SHA512": 64,
        "HMAC_SHA3_256": 32, "HMAC_SHA3_512": 64,
        "HMAC_SHA1": 20, "HMAC_MD5": 16,
    }

    for name, size in expected_tag_sizes.items():
        algo = MACAlgorithm[name]
        got = MAC.TAG_SIZES.get(algo)
        log.check(got == size, f"TAG_SIZES[{name}]", expected=size, got=got)

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional MAC tests")
        return

    log.section("MAC constructor")

    for algo in MACAlgorithm:
        m = MAC(algo, TEST_KEY_256)
        log.check(m.algorithm == algo, f"MAC({algo.name}).algorithm")
        log.check(m.key == TEST_KEY_256, f"MAC({algo.name}).key set")

    log.section("SipHash constructor")

    sh8 = SipHash(c=2, d=4, output_size=8)
    log.check(sh8.output_size == 8, "SipHash(2,4,8).output_size", value=8)
    sh16 = SipHash(c=2, d=4, output_size=16)
    log.check(sh16.output_size == 16, "SipHash(2,4,16).output_size", value=16)

    log.section("Functional: MAC compute + verify")

    for algo in MACAlgorithm:
        m = MAC(algo, TEST_KEY_256)
        tag = m.compute(TEST_DATA_SHORT)
        log.check(len(tag) == MAC.TAG_SIZES[algo], f"{algo.name} tag size", size=len(tag))
        log.check(m.verify(TEST_DATA_SHORT, tag) is True, f"{algo.name} verify correct")
        log.check(m.verify(TEST_DATA_SHORT, b"\x00" * len(tag)) is False, f"{algo.name} verify wrong")

    log.section("Functional: SipHash compute")

    sh = SipHash(c=2, d=4, output_size=8)
    tag = sh.compute(TEST_SIPHASH_KEY, TEST_DATA_SHORT)
    log.check(len(tag) == 8, "SipHash-2-4 tag size", size=len(tag))
