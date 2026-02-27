"""Test AES AEAD (Authenticated Encryption with Associated Data) modes: 7 modes total.

GCM, CCM, OCB, EAX, GCM-SIV, SIV, Poly1305
"""

from ..common import TestLogger


def run():
    """Run all AES AEAD mode tests."""
    log = TestLogger("test_aes_aead", "core")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("AES AEAD - Enum Validation")
    
    # All 7 AEAD modes
    modes = [
        (nextssl.AESMode.GCM, "GCM"),
        (nextssl.AESMode.CCM, "CCM"),
        (nextssl.AESMode.OCB, "OCB"),
        (nextssl.AESMode.EAX, "EAX"),
        (nextssl.AESMode.GCM_SIV, "GCM-SIV"),
        (nextssl.AESMode.SIV, "SIV"),
        (nextssl.AESMode.POLY1305, "Poly1305"),
    ]
    
    # Test 1: Enum existence
    for mode_enum, name in modes:
        try:
            log.pass_(f"{name} enum", value=mode_enum.value)
        except Exception as e:
            log.fail(f"{name} enum", error=str(e))
    
    log.section("AES AEAD - Encrypt/Decrypt with Authentication")
    
    # Test 2: AEAD encrypt → decrypt → verify cycle
    test_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes for AES-256
    test_nonce = b"0123456789ab"  # 12 bytes nonce for GCM
    test_plaintext = b"Authenticated message for AEAD testing"
    test_aad = b"Additional authenticated data"  # Associated data
    
    # Test GCM (most common AEAD mode)
    if hasattr(nextssl.AESMode, 'GCM'):
        try:
            aes_gcm = nextssl.AES(nextssl.AESMode.GCM)
            
            # Encrypt with authentication
            # AEAD typically returns (ciphertext, tag)
            result = aes_gcm.encrypt(test_key, test_nonce, test_plaintext, test_aad)
            
            if isinstance(result, tuple):
                ciphertext, tag = result
                log.data("GCM ciphertext", ciphertext.hex())
                log.data("GCM tag", tag.hex())
                
                # Decrypt and verify
                decrypted = aes_gcm.decrypt(test_key, test_nonce, ciphertext, tag, test_aad)
                
                if decrypted == test_plaintext:
                    log.pass_("GCM roundtrip", plaintext_len=len(test_plaintext))
                else:
                    log.fail("GCM roundtrip", expected_len=len(test_plaintext), got_len=len(decrypted))
            else:
                # Combined ciphertext+tag
                log.data("GCM output", result.hex())
                # Decrypt
                decrypted = aes_gcm.decrypt(test_key, test_nonce, result, test_aad)
                
                if decrypted == test_plaintext:
                    log.pass_("GCM roundtrip", plaintext_len=len(test_plaintext))
                else:
                    log.fail("GCM roundtrip", reason="plaintext mismatch")
        except Exception as e:
            log.fail("GCM roundtrip", error=str(e))
    
    log.section("AES AEAD - Tamper Detection")
    
    # Test 3: Modified ciphertext → authentication failure
    if hasattr(nextssl.AESMode, 'GCM'):
        try:
            aes_gcm = nextssl.AES(nextssl.AESMode.GCM)
            
            # Encrypt
            result = aes_gcm.encrypt(test_key, test_nonce, test_plaintext, test_aad)
            
            if isinstance(result, tuple):
                ciphertext, tag = result
                # Tamper with ciphertext
                tampered_ciphertext = bytes([b ^ 0xFF for b in ciphertext[:10]]) + ciphertext[10:]
                
                try:
                    decrypted = aes_gcm.decrypt(test_key, test_nonce, tampered_ciphertext, tag, test_aad)
                    log.fail("GCM tamper_detection", reason="accepted tampered data")
                except Exception:
                    log.pass_("GCM tamper_detection", detected=True)
            else:
                # Tamper with combined output
                tampered = bytes([b ^ 0xFF for b in result[:10]]) + result[10:]
                try:
                    decrypted = aes_gcm.decrypt(test_key, test_nonce, tampered, test_aad)
                    log.fail("GCM tamper_detection", reason="accepted tampered data")
                except Exception:
                    log.pass_("GCM tamper_detection", detected=True)
        except Exception as e:
            log.fail("GCM tamper_detection", error=str(e))
    
    log.section("AES AEAD - AAD Modification Detection")
    
    # Test 4: Different AAD → authentication failure
    if hasattr(nextssl.AESMode, 'GCM'):
        try:
            aes_gcm = nextssl.AES(nextssl.AESMode.GCM)
            
            # Encrypt with original AAD
            result = aes_gcm.encrypt(test_key, test_nonce, test_plaintext, test_aad)
            
            # Try to decrypt with different AAD
            different_aad = b"Different associated data"
            
            try:
                if isinstance(result, tuple):
                    ciphertext, tag = result
                    decrypted = aes_gcm.decrypt(test_key, test_nonce, ciphertext, tag, different_aad)
                else:
                    decrypted = aes_gcm.decrypt(test_key, test_nonce, result, different_aad)
                
                log.fail("GCM aad_detection", reason="accepted different AAD")
            except Exception:
                log.pass_("GCM aad_detection", detected=True)
        except Exception as e:
            log.fail("GCM aad_detection", error=str(e))
    
    log.section("AES AEAD - Other AEAD Modes")
    
    # Test 5: Other AEAD mode availability
    other_modes = [
        ("CCM", "Counter with CBC-MAC"),
        ("OCB", "Offset Codebook Mode"),
        ("EAX", "EAX mode"),
        ("GCM_SIV", "GCM-SIV (nonce-misuse resistant)"),
        ("SIV", "Synthetic IV mode"),
        ("POLY1305", "AES-Poly1305"),
    ]
    
    for mode_name, description in other_modes:
        try:
            if hasattr(nextssl.AESMode, mode_name):
                mode_enum = getattr(nextssl.AESMode, mode_name)
                aes = nextssl.AES(mode_enum)
                log.pass_(f"{mode_name} available", desc=description)
            else:
                log.info(f"{mode_name} - not implemented yet")
        except Exception as e:
            log.fail(f"{mode_name} check", error=str(e))
    
    log.section("AES AEAD - Security Properties")
    
    log.info("AEAD modes provide:")
    log.info("  ✓ Confidentiality (encryption)")
    log.info("  ✓ Integrity (authentication tag)")
    log.info("  ✓ Authentication (AAD protection)")
    log.info("  ✓ Tamper detection (invalid tag on modification)")
    log.info("")
    log.info("Recommended modes:")
    log.info("  - GCM: Most widely used, hardware-accelerated")
    log.info("  - GCM-SIV: Nonce-misuse resistant")
    log.info("  - ChaCha20-Poly1305: Fast in software (see stream_aead tests)")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
