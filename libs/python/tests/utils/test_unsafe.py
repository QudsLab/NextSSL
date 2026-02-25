"""Unsafe/legacy hash tests - 10 broken algorithms."""

from .common import has_binaries, TEST_DATA_EMPTY, TEST_DATA_SHORT, VECTORS


def run(log):
    from nextssl.unsafe import UnsafeHashAlgorithm, UnsafeHash, md5, sha1, sha0, md4, md2

    # ------------------------------------------------------------------
    log.section("UnsafeHashAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "MD2": 0, "MD4": 1, "MD5": 2, "SHA0": 3, "SHA1": 4,
        "HAS160": 10, "RIPEMD128": 11, "RIPEMD256": 12, "RIPEMD320": 13,
        "NTLM": 20,
    }

    for name, val in expected.items():
        member = UnsafeHashAlgorithm[name]
        log.check(member.value == val, f"UnsafeHashAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(UnsafeHashAlgorithm) == len(expected),
              "UnsafeHashAlgorithm member count", got=len(UnsafeHashAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("UnsafeHash.DIGEST_SIZES coverage (static)")
    # ------------------------------------------------------------------

    expected_sizes = {
        "MD2": 16, "MD4": 16, "MD5": 16, "SHA0": 20, "SHA1": 20,
        "HAS160": 20, "RIPEMD128": 16, "RIPEMD256": 32, "RIPEMD320": 40,
        "NTLM": 16,
    }

    for name, size in expected_sizes.items():
        algo = UnsafeHashAlgorithm[name]
        got = UnsafeHash.DIGEST_SIZES.get(algo)
        log.check(got == size, f"DIGEST_SIZES[{name}]", expected=size, got=got)

    # ------------------------------------------------------------------
    log.section("Convenience functions exist")
    # ------------------------------------------------------------------

    log.check(callable(md5), "md5 is callable")
    log.check(callable(sha1), "sha1 is callable")
    log.check(callable(sha0), "sha0 is callable")
    log.check(callable(md4), "md4 is callable")
    log.check(callable(md2), "md2 is callable")

    # ------------------------------------------------------------------
    # Functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping functional unsafe tests")
        return

    log.section("Functional: KAT vectors")

    md5_empty = md5(TEST_DATA_EMPTY)
    log.check(md5_empty.hex() == VECTORS["MD5"][b""],
              "md5('') KAT", expected=VECTORS["MD5"][b""], got=md5_empty.hex())

    sha1_empty = sha1(TEST_DATA_EMPTY)
    log.check(sha1_empty.hex() == VECTORS["SHA1"][b""],
              "sha1('') KAT", expected=VECTORS["SHA1"][b""], got=sha1_empty.hex())

    log.section("Functional: digest sizes")

    for algo in UnsafeHashAlgorithm:
        h = UnsafeHash(algo)
        digest = h.digest(TEST_DATA_SHORT)
        expected_size = UnsafeHash.DIGEST_SIZES[algo]
        log.check(len(digest) == expected_size,
                  f"{algo.name} digest size", expected=expected_size, got=len(digest))

    log.section("Functional: determinism")

    h = UnsafeHash(UnsafeHashAlgorithm.MD5)
    d1 = h.digest(TEST_DATA_SHORT)
    d2 = h.digest(TEST_DATA_SHORT)
    log.check(d1 == d2, "MD5 deterministic")
