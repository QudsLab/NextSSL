"""PQC Signature tests - 32 algorithms."""

from .common import has_binaries, TEST_MESSAGE


def run(log):
    from nextssl.pqc.sign_complete import SignAlgorithm, Sign

    # ------------------------------------------------------------------
    log.section("SignAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "ML_DSA_44": 0, "ML_DSA_65": 1, "ML_DSA_87": 2,
        "FALCON_512": 10, "FALCON_1024": 11,
        "SPHINCS_SHAKE_128F_SIMPLE": 20, "SPHINCS_SHAKE_128F_ROBUST": 21,
        "SPHINCS_SHAKE_128S_SIMPLE": 22, "SPHINCS_SHAKE_128S_ROBUST": 23,
        "SPHINCS_SHAKE_192F_SIMPLE": 24, "SPHINCS_SHAKE_192F_ROBUST": 25,
        "SPHINCS_SHAKE_192S_SIMPLE": 26, "SPHINCS_SHAKE_192S_ROBUST": 27,
        "SPHINCS_SHAKE_256F_SIMPLE": 28, "SPHINCS_SHAKE_256F_ROBUST": 29,
        "SPHINCS_SHAKE_256S_SIMPLE": 30, "SPHINCS_SHAKE_256S_ROBUST": 31,
        "SPHINCS_SHA2_128F_SIMPLE": 40, "SPHINCS_SHA2_128F_ROBUST": 41,
        "SPHINCS_SHA2_128S_SIMPLE": 42, "SPHINCS_SHA2_128S_ROBUST": 43,
        "SPHINCS_SHA2_192F_SIMPLE": 44, "SPHINCS_SHA2_192F_ROBUST": 45,
        "SPHINCS_SHA2_192S_SIMPLE": 46, "SPHINCS_SHA2_192S_ROBUST": 47,
        "SPHINCS_SHA2_256F_SIMPLE": 48, "SPHINCS_SHA2_256F_ROBUST": 49,
        "SPHINCS_SHA2_256S_SIMPLE": 50, "SPHINCS_SHA2_256S_ROBUST": 51,
    }

    for name, val in expected.items():
        member = SignAlgorithm[name]
        log.check(member.value == val, f"SignAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(SignAlgorithm) == len(expected),
              "SignAlgorithm member count", got=len(SignAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("Sign.PARAMS coverage (static)")
    # ------------------------------------------------------------------

    for algo in SignAlgorithm:
        log.check(algo in Sign.PARAMS, f"PARAMS[{algo.name}]")

    # NIST sizes spot check
    nist = {
        "ML_DSA_44": (1312, 2528, 2420),
        "ML_DSA_65": (1952, 4000, 3293),
        "ML_DSA_87": (2592, 4864, 4595),
        "FALCON_512": (897, 1281, 690),
        "FALCON_1024": (1793, 2305, 1330),
    }
    for name, (pk, sk, sig) in nist.items():
        algo = SignAlgorithm[name]
        p = Sign.PARAMS[algo]
        log.check(p == (pk, sk, sig), f"PARAMS[{name}] NIST match",
                  expected=f"({pk},{sk},{sig})", got=str(p))

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional sign tests")
        return

    log.section("Sign constructor + sizes")

    for algo in SignAlgorithm:
        s = Sign(algo)
        log.check(s.algorithm == algo, f"Sign({algo.name}).algorithm")
        pk, sk, sig = Sign.PARAMS[algo]
        log.check(s.public_key_size == pk, f"Sign({algo.name}).pk_size", expected=pk, got=s.public_key_size)
        log.check(s.secret_key_size == sk, f"Sign({algo.name}).sk_size", expected=sk, got=s.secret_key_size)
        log.check(s.signature_size == sig, f"Sign({algo.name}).sig_size", expected=sig, got=s.signature_size)

    log.section("Functional: keygen + sign + verify roundtrip")

    for algo in [SignAlgorithm.ML_DSA_44, SignAlgorithm.ML_DSA_65, SignAlgorithm.ML_DSA_87, SignAlgorithm.FALCON_512]:
        s = Sign(algo)
        pk, sk = s.keypair()
        log.check(len(pk) == s.public_key_size, f"{algo.name} pk size", size=len(pk))
        log.check(len(sk) == s.secret_key_size, f"{algo.name} sk size", size=len(sk))

        signature = s.sign(TEST_MESSAGE, sk)
        log.check(len(signature) <= s.signature_size, f"{algo.name} sig size", size=len(signature))

        valid = s.verify(TEST_MESSAGE, signature, pk)
        log.check(valid is True, f"{algo.name} verify valid")

        invalid = s.verify(b"wrong message", signature, pk)
        log.check(invalid is False, f"{algo.name} verify invalid")
