"""Cipher tests - 16 AES modes + ChaCha20-Poly1305."""

from .common import has_binaries, TEST_KEY_128, TEST_KEY_192, TEST_KEY_256, TEST_NONCE_12, TEST_NONCE_24, TEST_DATA_BLOCK


def run(log):
    from nextssl.primitives.cipher import AESMode

    # ------------------------------------------------------------------
    log.section("AESMode enum validation")
    # ------------------------------------------------------------------

    expected = {
        "ECB": 0, "CBC": 1, "CFB": 2, "OFB": 3, "CTR": 4, "XTS": 5,
        "KW": 10,
        "FPE_FF1": 20, "FPE_FF3": 21,
        "GCM": 100, "CCM": 101, "OCB": 102, "EAX": 103,
        "GCM_SIV": 104, "SIV": 105, "POLY1305": 106,
        "CHACHA20_POLY1305": 200,
    }

    for name, val in expected.items():
        member = AESMode[name]
        log.check(member.value == val, f"AESMode.{name}", value=member.value, expected=val)

    log.check(len(AESMode) == len(expected),
              "AESMode member count", got=len(AESMode), expected=len(expected))

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional cipher tests")
        return

    from nextssl.primitives.cipher import AES, ChaCha20Poly1305

    log.section("AES constructor - key validation")

    for key, label in [(TEST_KEY_128, "128"), (TEST_KEY_192, "192"), (TEST_KEY_256, "256")]:
        aes = AES(key, AESMode.GCM)
        log.check(aes.key == key, f"AES-{label} key set")
        log.check(aes.mode == AESMode.GCM, f"AES-{label} mode set")

    log.section("AES constructor - all modes")

    for mode in AESMode:
        if mode == AESMode.CHACHA20_POLY1305:
            continue
        aes = AES(TEST_KEY_256, mode)
        log.check(aes.mode == mode, f"AES({mode.name}).mode", value=aes.mode.name)

    log.section("ChaCha20Poly1305 constructor")

    cc = ChaCha20Poly1305()
    log.check(cc is not None, "ChaCha20Poly1305 instantiates")

    log.section("Functional: AES-GCM encrypt/decrypt roundtrip")

    aes = AES(TEST_KEY_256, AESMode.GCM)
    ct, tag = aes.encrypt(TEST_DATA_BLOCK, TEST_NONCE_12)
    log.check(len(ct) == len(TEST_DATA_BLOCK), "GCM ct size matches pt")
    log.check(len(tag) == 16, "GCM tag is 16 bytes")

    pt = aes.decrypt(ct, TEST_NONCE_12, tag)
    log.check(pt == TEST_DATA_BLOCK, "GCM roundtrip matches")

    log.section("Functional: ChaCha20-Poly1305 encrypt/decrypt roundtrip")

    cc = ChaCha20Poly1305()
    ct, tag = cc.encrypt(TEST_KEY_256, TEST_NONCE_24, TEST_DATA_BLOCK)
    pt = cc.decrypt(TEST_KEY_256, TEST_NONCE_24, ct, tag)
    log.check(pt == TEST_DATA_BLOCK, "ChaCha20 roundtrip matches")
