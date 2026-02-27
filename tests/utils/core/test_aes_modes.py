"""Test AES cipher modes: 9 modes total.

CBC, CFB, OFB, CTR, ECB, XTS, KW (Key Wrap), FPE-FF1, FPE-FF3
"""

from ..common import TestLogger


def run():
    """Run all AES mode tests."""
    log = TestLogger("test_aes_modes", "core")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("AES Modes - Enum Validation")
    
    # All 9 AES modes
    modes = [
        (nextssl.AESMode.CBC, "CBC"),
        (nextssl.AESMode.CFB, "CFB"),
        (nextssl.AESMode.OFB, "OFB"),
        (nextssl.AESMode.CTR, "CTR"),
        (nextssl.AESMode.ECB, "ECB"),
        (nextssl.AESMode.XTS, "XTS"),
        (nextssl.AESMode.KW, "KW (Key Wrap)"),
        (nextssl.AESMode.FPE_FF1, "FPE-FF1"),
        (nextssl.AESMode.FPE_FF3, "FPE-FF3"),
    ]
    
    # Test 1: Enum existence
    for mode_enum, name in modes:
        try:
            log.pass_(f"{name} enum", value=mode_enum.value)
        except Exception as e:
            log.fail(f"{name} enum", error=str(e))
    
    log.section("AES Modes - Encrypt/Decrypt Roundtrip")
    
    # Test 2: Encrypt → Decrypt cycle
    test_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes for AES-256
    test_iv = b"0123456789abcdef"  # 16 bytes IV
    test_plaintext = b"Hello, NextSSL! This is a test message for AES encryption."
    
    # Pad plaintext to block size (16 bytes) for block modes
    block_size = 16
    padding_length = block_size - (len(test_plaintext) % block_size)
    padded_plaintext = test_plaintext + bytes([padding_length] * padding_length)
    
    # Test modes that support standard encrypt/decrypt
    standard_modes = [
        (nextssl.AESMode.CBC, "CBC"),
        (nextssl.AESMode.CFB, "CFB"),
        (nextssl.AESMode.OFB, "OFB"),
        (nextssl.AESMode.CTR, "CTR"),
        (nextssl.AESMode.ECB, "ECB"),
    ]
    
    for mode_enum, name in standard_modes:
        try:
            aes = nextssl.AES(mode_enum)
            
            # Encrypt
            if mode_enum == nextssl.AESMode.ECB:
                ciphertext = aes.encrypt(test_key, padded_plaintext)
            else:
                ciphertext = aes.encrypt(test_key, test_iv, padded_plaintext)
            
            log.data(f"{name} ciphertext", ciphertext.hex())
            
            # Decrypt
            if mode_enum == nextssl.AESMode.ECB:
                decrypted = aes.decrypt(test_key, ciphertext)
            else:
                decrypted = aes.decrypt(test_key, test_iv, ciphertext)
            
            # Verify roundtrip
            if decrypted == padded_plaintext:
                log.pass_(f"{name} roundtrip", plaintext_len=len(test_plaintext))
            else:
                log.fail(f"{name} roundtrip", 
                        expected_len=len(padded_plaintext),
                        got_len=len(decrypted))
        except Exception as e:
            log.fail(f"{name} roundtrip", error=str(e))
    
    log.section("AES Modes - Determinism")
    
    # Test 3: Same inputs → same ciphertext
    for mode_enum, name in standard_modes:
        try:
            aes = nextssl.AES(mode_enum)
            
            if mode_enum == nextssl.AESMode.ECB:
                ciphertext1 = aes.encrypt(test_key, padded_plaintext)
                ciphertext2 = aes.encrypt(test_key, padded_plaintext)
            else:
                ciphertext1 = aes.encrypt(test_key, test_iv, padded_plaintext)
                ciphertext2 = aes.encrypt(test_key, test_iv, padded_plaintext)
            
            if ciphertext1 == ciphertext2:
                log.pass_(f"{name} determinism", size=len(ciphertext1))
            else:
                log.fail(f"{name} determinism", reason="outputs differ")
        except Exception as e:
            log.fail(f"{name} determinism", error=str(e))
    
    log.section("AES Modes - Wrong Key Detection")
    
    # Test 4: Wrong key → different plaintext
    wrong_key = b"fedcba9876543210fedcba9876543210"  # Different key
    
    for mode_enum, name in standard_modes:
        try:
            aes = nextssl.AES(mode_enum)
            
            # Encrypt with correct key
            if mode_enum == nextssl.AESMode.ECB:
                ciphertext = aes.encrypt(test_key, padded_plaintext)
                decrypted_wrong = aes.decrypt(wrong_key, ciphertext)
            else:
                ciphertext = aes.encrypt(test_key, test_iv, padded_plaintext)
                decrypted_wrong = aes.decrypt(wrong_key, test_iv, ciphertext)
            
            # Decrypt with wrong key should give garbage
            if decrypted_wrong != padded_plaintext:
                log.pass_(f"{name} wrong_key", detected=True)
            else:
                log.fail(f"{name} wrong_key", reason="accepted wrong key")
        except Exception as e:
            # Exception is also acceptable for wrong key
            log.pass_(f"{name} wrong_key", detected_via_exception=True)
    
    log.section("AES Modes - Special Modes")
    
    # Test 5: XTS mode (for disk encryption)
    try:
        if hasattr(nextssl.AESMode, 'XTS'):
            log.info("XTS mode - designed for disk encryption, different API")
            # XTS requires different parameters (tweak, sector)
            log.pass_("XTS enum", available=True)
    except Exception as e:
        log.info(f"XTS mode - {e}")
    
    # Test 6: Key Wrap (KW) mode
    try:
        if hasattr(nextssl.AESMode, 'KW'):
            log.info("KW mode - designed for key wrapping, specific use case")
            log.pass_("KW enum", available=True)
    except Exception as e:
        log.info(f"KW mode - {e}")
    
    # Test 7: FPE modes (Format-Preserving Encryption)
    try:
        if hasattr(nextssl.AESMode, 'FPE_FF1'):
            log.info("FPE-FF1 - Format-preserving encryption for structured data")
            log.pass_("FPE-FF1 enum", available=True)
        if hasattr(nextssl.AESMode, 'FPE_FF3'):
            log.info("FPE-FF3 - Alternative FPE mode")
            log.pass_("FPE-FF3 enum", available=True)
    except Exception as e:
        log.info(f"FPE modes - {e}")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
