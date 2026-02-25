"""Hash algorithm tests - 34 algorithms."""

from .common import has_binaries, TEST_DATA_EMPTY, TEST_DATA_SHORT, TEST_DATA_BLOCK, VECTORS


def run(log):
    from nextssl.hash_complete import HashAlgorithm, DIGEST_SIZES

    # ------------------------------------------------------------------
    log.section("HashAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected_members = {
        "SHA224": 0, "SHA256": 1, "SHA384": 2, "SHA512": 3,
        "SHA512_224": 4, "SHA512_256": 5,
        "BLAKE2B": 10, "BLAKE2S": 11, "BLAKE3": 12,
        "ARGON2D": 100, "ARGON2I": 101, "ARGON2ID": 102,
        "SHA3_224": 200, "SHA3_256": 201, "SHA3_384": 202, "SHA3_512": 203,
        "KECCAK_224": 210, "KECCAK_256": 211, "KECCAK_384": 212, "KECCAK_512": 213,
        "SHAKE128": 220, "SHAKE256": 221,
        "MD5": 300, "SHA1": 301, "RIPEMD160": 302,
        "WHIRLPOOL": 303, "WHIRLPOOL0": 304, "WHIRLPOOLT": 305, "NT": 310,
        "MD2": 400, "MD4": 401, "SHA0": 402,
        "HAS160": 403, "RIPEMD128": 404, "RIPEMD256": 405, "RIPEMD320": 406,
    }

    for name, val in expected_members.items():
        member = HashAlgorithm[name]
        log.check(member.value == val, f"HashAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(HashAlgorithm) == len(expected_members),
              "HashAlgorithm member count",
              got=len(HashAlgorithm), expected=len(expected_members))

    # ------------------------------------------------------------------
    log.section("DIGEST_SIZES coverage")
    # ------------------------------------------------------------------

    expected_sizes = {
        "SHA224": 28, "SHA256": 32, "SHA384": 48, "SHA512": 64,
        "SHA512_224": 28, "SHA512_256": 32,
        "BLAKE2B": 64, "BLAKE2S": 32, "BLAKE3": 32,
        "SHA3_224": 28, "SHA3_256": 32, "SHA3_384": 48, "SHA3_512": 64,
        "KECCAK_224": 28, "KECCAK_256": 32, "KECCAK_384": 48, "KECCAK_512": 64,
        "MD5": 16, "SHA1": 20, "RIPEMD160": 20,
        "WHIRLPOOL": 64, "WHIRLPOOL0": 64, "WHIRLPOOLT": 64, "NT": 16,
        "MD2": 16, "MD4": 16, "SHA0": 20,
        "HAS160": 20, "RIPEMD128": 16, "RIPEMD256": 32, "RIPEMD320": 40,
    }

    for name, size in expected_sizes.items():
        algo = HashAlgorithm[name]
        got = DIGEST_SIZES.get(algo)
        log.check(got == size, f"DIGEST_SIZES[{name}]", expected=size, got=got)

    # Argon2 variants not in DIGEST_SIZES (variable output)
    for name in ["ARGON2D", "ARGON2I", "ARGON2ID", "SHAKE128", "SHAKE256"]:
        algo = HashAlgorithm[name]
        log.check(algo in HashAlgorithm, f"HashAlgorithm.{name} exists (no fixed digest)")

    # ------------------------------------------------------------------
    # Everything below requires C binaries (constructors load native libs)
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional tests")
        return

    from nextssl.hash_complete import Hash, BLAKE2, SHAKE, Argon2

    log.section("Hash constructor validation")

    for algo in HashAlgorithm:
        h = Hash(algo)
        log.check(h.algorithm == algo, f"Hash({algo.name}).algorithm", value=h.algorithm.name)
        log.check(h.digest_size == DIGEST_SIZES.get(algo, 32),
                  f"Hash({algo.name}).digest_size", size=h.digest_size)

    log.section("BLAKE2 constructor validation")

    b2b = BLAKE2('b')
    log.check(b2b.variant == 'b', "BLAKE2('b').variant", value=b2b.variant)
    log.check(b2b.max_output == 64, "BLAKE2('b').max_output", value=b2b.max_output)

    b2s = BLAKE2('s')
    log.check(b2s.variant == 's', "BLAKE2('s').variant", value=b2s.variant)
    log.check(b2s.max_output == 32, "BLAKE2('s').max_output", value=b2s.max_output)

    log.section("SHAKE constructor validation")

    s128 = SHAKE(128)
    log.check(s128.bits == 128, "SHAKE(128).bits", value=s128.bits)
    s256 = SHAKE(256)
    log.check(s256.bits == 256, "SHAKE(256).bits", value=s256.bits)

    log.section("Argon2 constructor validation")

    for variant in ('d', 'i', 'id'):
        a = Argon2(variant)
        log.check(a.variant == variant, f"Argon2('{variant}').variant", value=a.variant)

    log.section("Functional: KAT vectors")

    for algo_name, vectors in VECTORS.items():
        if algo_name not in expected_members:
            continue
        algo = HashAlgorithm[algo_name]
        for data, expected_hex in vectors.items():
            if expected_hex is None:
                continue
            h = Hash(algo)
            digest = h.digest(data)
            got_hex = digest.hex()
            log.check(
                got_hex == expected_hex,
                f"{algo_name}({data!r:.20})",
                expected=expected_hex[:16] + "...",
                got=got_hex[:16] + "...",
                size=len(digest),
            )

    log.section("Functional: determinism")

    for algo in [HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.BLAKE3]:
        h = Hash(algo)
        d1 = h.digest(TEST_DATA_SHORT)
        d2 = h.digest(TEST_DATA_SHORT)
        log.check(d1 == d2, f"{algo.name} deterministic", size=len(d1))

    log.section("Functional: different inputs")

    h = Hash(HashAlgorithm.SHA256)
    d_empty = h.digest(TEST_DATA_EMPTY)
    d_short = h.digest(TEST_DATA_SHORT)
    log.check(d_empty != d_short, "SHA256 empty != short")
