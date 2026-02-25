"""PQC KEM tests - 16 algorithms."""

from .common import has_binaries, TEST_MESSAGE


def run(log):
    from nextssl.pqc.kem_complete import KEMAlgorithm

    # ------------------------------------------------------------------
    log.section("KEMAlgorithm enum validation")
    # ------------------------------------------------------------------

    expected = {
        "ML_KEM_512": 0, "ML_KEM_768": 1, "ML_KEM_1024": 2,
        "HQC_128": 10, "HQC_192": 11, "HQC_256": 12,
        "MCELIECE_348864": 20, "MCELIECE_348864F": 21,
        "MCELIECE_460896": 22, "MCELIECE_460896F": 23,
        "MCELIECE_6688128": 24, "MCELIECE_6688128F": 25,
        "MCELIECE_6960119": 26, "MCELIECE_6960119F": 27,
        "MCELIECE_8192128": 28, "MCELIECE_8192128F": 29,
    }

    for name, val in expected.items():
        member = KEMAlgorithm[name]
        log.check(member.value == val, f"KEMAlgorithm.{name}", value=member.value, expected=val)

    log.check(len(KEMAlgorithm) == len(expected),
              "KEMAlgorithm member count", got=len(KEMAlgorithm), expected=len(expected))

    # ------------------------------------------------------------------
    log.section("KEM.PARAMS coverage (static)")
    # ------------------------------------------------------------------

    from nextssl.pqc.kem_complete import KEM
    for algo in KEMAlgorithm:
        log.check(algo in KEM.PARAMS, f"PARAMS[{algo.name}]")

    # NIST sizes spot check
    nist = {
        "ML_KEM_512": (800, 1632, 768, 32),
        "ML_KEM_768": (1184, 2400, 1088, 32),
        "ML_KEM_1024": (1568, 3168, 1568, 32),
    }
    for name, (pk, sk, ct, ss) in nist.items():
        algo = KEMAlgorithm[name]
        p = KEM.PARAMS[algo]
        log.check(p == (pk, sk, ct, ss), f"PARAMS[{name}] NIST match",
                  expected=f"({pk},{sk},{ct},{ss})", got=str(p))

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional KEM tests")
        return

    log.section("KEM constructor + sizes")

    for algo in KEMAlgorithm:
        k = KEM(algo)
        log.check(k.algorithm == algo, f"KEM({algo.name}).algorithm")
        pk, sk, ct, ss = KEM.PARAMS[algo]
        log.check(k.public_key_size == pk, f"KEM({algo.name}).pk_size", expected=pk, got=k.public_key_size)
        log.check(k.secret_key_size == sk, f"KEM({algo.name}).sk_size", expected=sk, got=k.secret_key_size)
        log.check(k.ciphertext_size == ct, f"KEM({algo.name}).ct_size", expected=ct, got=k.ciphertext_size)
        log.check(k.shared_secret_size == ss, f"KEM({algo.name}).ss_size", expected=ss, got=k.shared_secret_size)

    log.section("Functional: keygen + encaps + decaps roundtrip")

    for algo in [KEMAlgorithm.ML_KEM_512, KEMAlgorithm.ML_KEM_768, KEMAlgorithm.ML_KEM_1024]:
        k = KEM(algo)
        pk, sk = k.keypair()
        log.check(len(pk) == k.public_key_size, f"{algo.name} pk size", size=len(pk))
        log.check(len(sk) == k.secret_key_size, f"{algo.name} sk size", size=len(sk))

        ct, ss_enc = k.encapsulate(pk)
        log.check(len(ct) == k.ciphertext_size, f"{algo.name} ct size", size=len(ct))
        log.check(len(ss_enc) == k.shared_secret_size, f"{algo.name} ss size", size=len(ss_enc))

        ss_dec = k.decapsulate(ct, sk)
        log.check(ss_enc == ss_dec, f"{algo.name} roundtrip match")
