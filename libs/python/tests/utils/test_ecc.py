"""ECC tests - Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2."""

from .common import has_binaries, TEST_MESSAGE


def run(log):
    from nextssl.primitives.ecc_complete import ECCCurve, Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2

    # ------------------------------------------------------------------
    log.section("ECCCurve enum validation")
    # ------------------------------------------------------------------

    expected = {
        "ED25519": 0, "ED448": 1, "CURVE25519": 2, "CURVE448": 3, "RISTRETTO255": 4,
    }

    for name, val in expected.items():
        member = ECCCurve[name]
        log.check(member.value == val, f"ECCCurve.{name}", value=member.value, expected=val)

    # ------------------------------------------------------------------
    log.section("ECC class constants (static, no constructor)")
    # ------------------------------------------------------------------

    log.check(Ed25519.PRIVATE_KEY_SIZE == 32, "Ed25519.PRIVATE_KEY_SIZE", value=32)
    log.check(Ed25519.PUBLIC_KEY_SIZE == 32, "Ed25519.PUBLIC_KEY_SIZE", value=32)
    log.check(Ed25519.SIGNATURE_SIZE == 64, "Ed25519.SIGNATURE_SIZE", value=64)

    log.check(Ed448.PRIVATE_KEY_SIZE == 57, "Ed448.PRIVATE_KEY_SIZE", value=57)
    log.check(Ed448.PUBLIC_KEY_SIZE == 57, "Ed448.PUBLIC_KEY_SIZE", value=57)
    log.check(Ed448.SIGNATURE_SIZE == 114, "Ed448.SIGNATURE_SIZE", value=114)

    log.check(Curve25519.PRIVATE_KEY_SIZE == 32, "Curve25519.PRIVATE_KEY_SIZE", value=32)
    log.check(Curve25519.PUBLIC_KEY_SIZE == 32, "Curve25519.PUBLIC_KEY_SIZE", value=32)
    log.check(Curve25519.SHARED_SECRET_SIZE == 32, "Curve25519.SHARED_SECRET_SIZE", value=32)

    log.check(Curve448.PRIVATE_KEY_SIZE == 56, "Curve448.PRIVATE_KEY_SIZE", value=56)
    log.check(Curve448.PUBLIC_KEY_SIZE == 56, "Curve448.PUBLIC_KEY_SIZE", value=56)
    log.check(Curve448.SHARED_SECRET_SIZE == 56, "Curve448.SHARED_SECRET_SIZE", value=56)

    log.check(Ristretto255.ELEMENT_SIZE == 32, "Ristretto255.ELEMENT_SIZE", value=32)
    log.check(Ristretto255.SCALAR_SIZE == 32, "Ristretto255.SCALAR_SIZE", value=32)

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional ECC tests")
        return

    log.section("ECC constructors")

    ed = Ed25519()
    log.check(ed is not None, "Ed25519 instantiates")
    ed4 = Ed448()
    log.check(ed4 is not None, "Ed448 instantiates")
    c25 = Curve25519()
    log.check(c25 is not None, "Curve25519 instantiates")
    c448 = Curve448()
    log.check(c448 is not None, "Curve448 instantiates")
    ris = Ristretto255()
    log.check(ris is not None, "Ristretto255 instantiates")
    eli = Elligator2()
    log.check(eli is not None, "Elligator2 instantiates")

    log.section("Functional: Ed25519 sign/verify")

    priv, pub = ed.keypair()
    log.check(len(priv) == 32, "Ed25519 priv size", size=len(priv))
    log.check(len(pub) == 32, "Ed25519 pub size", size=len(pub))

    sig = ed.sign(priv, TEST_MESSAGE)
    log.check(len(sig) == 64, "Ed25519 sig size", size=len(sig))

    valid = ed.verify(pub, TEST_MESSAGE, sig)
    log.check(valid is True, "Ed25519 verify valid")

    invalid = ed.verify(pub, b"wrong", sig)
    log.check(invalid is False, "Ed25519 verify invalid")

    log.section("Functional: Curve25519 ECDH")

    alice_priv, alice_pub = c25.keypair()
    bob_priv, bob_pub = c25.keypair()

    ss_alice = c25.scalarmult(alice_priv, bob_pub)
    ss_bob = c25.scalarmult(bob_priv, alice_pub)
    log.check(ss_alice == ss_bob, "Curve25519 ECDH shared secret match", size=len(ss_alice))
