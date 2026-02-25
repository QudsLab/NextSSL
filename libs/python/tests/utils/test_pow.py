"""PoW tests - Proof of Work client/server."""

from .common import has_binaries


def run(log):
    from nextssl.pow import PoWAlgorithm, PoWDifficultyModel

    # ------------------------------------------------------------------
    log.section("PoWAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "SHA256": 0, "SHA512": 1, "BLAKE2B": 2, "BLAKE2S": 3, "BLAKE3": 4,
        "ARGON2D": 100, "ARGON2I": 101, "ARGON2ID": 102,
        "SHA3_256": 200, "SHA3_512": 201, "KECCAK_256": 202, "SHAKE128": 203, "SHAKE256": 204,
        "MD5": 300, "SHA1": 301, "RIPEMD160": 302, "WHIRLPOOL": 303, "NT": 304,
        "MD2": 400, "MD4": 401, "SHA0": 402, "HAS160": 403,
        "RIPEMD128": 404, "RIPEMD256": 405, "RIPEMD320": 406,
    }

    for name, val in expected.items():
        member = PoWAlgorithm[name]
        log.check(member.value == val, f"PoWAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(PoWAlgorithm) == len(expected),
              "PoWAlgorithm member count", got=len(PoWAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("PoWDifficultyModel enum validation")
    # ------------------------------------------------------------------

    diff_expected = {
        "LEADING_ZEROS_BITS": 0, "LEADING_ZEROS_BYTES": 1, "LESS_THAN_TARGET": 2,
    }

    for name, val in diff_expected.items():
        member = PoWDifficultyModel[name]
        log.check(member.value == val, f"PoWDifficultyModel.{name}", value=member.value, expected=val)

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional PoW tests")
        return

    from nextssl.pow import PoWClient, PoWServer

    log.section("PoW constructors")

    for algo in [PoWAlgorithm.SHA256, PoWAlgorithm.BLAKE3, PoWAlgorithm.SHA3_256]:
        client = PoWClient(algo)
        log.check(client.algorithm == algo, f"PoWClient({algo.name}).algorithm")
        server = PoWServer(algo)
        log.check(server.algorithm == algo, f"PoWServer({algo.name}).algorithm")

    log.section("Functional: challenge + solve + verify")

    for algo in [PoWAlgorithm.SHA256, PoWAlgorithm.BLAKE3]:
        server = PoWServer(algo)
        client = PoWClient(algo)

        challenge = server.generate_challenge(difficulty=4)
        log.check(len(challenge) > 0, f"{algo.name} challenge generated", size=len(challenge))

        result = client.solve(challenge, difficulty=4)
        log.check(result is not None, f"{algo.name} solution found")

        nonce, iterations = result
        log.check(iterations > 0, f"{algo.name} iterations", count=iterations)

        valid = server.verify(challenge, nonce, difficulty=4)
        log.check(valid is True, f"{algo.name} verify valid")
