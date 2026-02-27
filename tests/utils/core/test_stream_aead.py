"""Test stream AEAD cipher: 1 algorithm total.

ChaCha20-Poly1305
"""

from ..common import TestLogger


def run():
    """Run ChaCha20-Poly1305 tests."""
    log = TestLogger("test_stream_aead", "core")
    
    try:
        import nextssl
    except ImportError as e:
        log.fail("Import nextssl", error=str(e))
        return log.summary()
    
    log.section("Stream AEAD - ChaCha20-Poly1305 Availability")
    
    # Test 1: Check if ChaCha20Poly1305 is available
    try:
        if hasattr(nextssl, 'ChaCha20Poly1305'):
            chacha = nextssl.ChaCha20Poly1305()
            log.pass_("ChaCha20Poly1305 class", available=True)
        else:
            log.fail("ChaCha20Poly1305 class", reason="not found")
            return log.summary()
    except Exception as e:
        log.fail("ChaCha20Poly1305 class", error=str(e))
        return log.summary()
    
    log.section("Stream AEAD - Encrypt/Decrypt with Authentication")
    
    # Test 2: Encrypt → decrypt cycle
    test_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes key
    test_nonce = b"0123456789ab"  # 12 bytes nonce
    test_plaintext = b"ChaCha20-Poly1305 authenticated encryption test"
    test_aad = b"Additional authenticated data"
    
    try:
        chacha = nextssl.ChaCha20Poly1305()
        
        # Encrypt
        result = chacha.encrypt(test_key, test_nonce, test_plaintext, test_aad)
        
        if isinstance(result, tuple):
            ciphertext, tag = result
            log.data("Ciphertext", ciphertext.hex())
            log.data("Tag", tag.hex())
            
            # Decrypt
            decrypted = chacha.decrypt(test_key, test_nonce, ciphertext, tag, test_aad)
        else:
            log.data("Output", result.hex())
            decrypted = chacha.decrypt(test_key, test_nonce, result, test_aad)
        
        if decrypted == test_plaintext:
            log.pass_("ChaCha20-Poly1305 roundtrip", plaintext_len=len(test_plaintext))
        else:
            log.fail("ChaCha20-Poly1305 roundtrip", reason="plaintext mismatch")
    except Exception as e:
        log.fail("ChaCha20-Poly1305 roundtrip", error=str(e))
    
    log.section("Stream AEAD - Tamper Detection")
    
    # Test 3: Modified ciphertext should fail authentication
    try:
        chacha = nextssl.ChaCha20Poly1305()
        result = chacha.encrypt(test_key, test_nonce, test_plaintext, test_aad)
        
        if isinstance(result, tuple):
            ciphertext, tag = result
            tampered = bytes([b ^ 1 for b in ciphertext[:5]]) + ciphertext[5:]
            try:
                decrypted = chacha.decrypt(test_key, test_nonce, tampered, tag, test_aad)
                log.fail("Tamper detection", reason="accepted tampered data")
            except Exception:
                log.pass_("Tamper detection", detected=True)
        else:
            tampered = bytes([b ^ 1 for b in result[:5]]) + result[5:]
            try:
                decrypted = chacha.decrypt(test_key, test_nonce, tampered, test_aad)
                log.fail("Tamper detection", reason="accepted tampered data")
            except Exception:
                log.pass_("Tamper detection", detected=True)
    except Exception as e:
        log.fail("Tamper detection", error=str(e))
    
    log.section("Stream AEAD - Performance Characteristics")
    
    log.info("ChaCha20-Poly1305 advantages:")
    log.info("  ✓ Fast in software (no AES hardware needed)")
    log.info("  ✓ Constant-time (resistant to timing attacks)")
    log.info("  ✓ IETF standard (RFC 8439)")
    log.info("  ✓ Used in TLS 1.3, WireGuard, SSH")
    log.info("")
    log.info("Compared to AES-GCM:")
    log.info("  - Faster on CPUs without AES-NI")
    log.info("  - Simpler implementation (fewer side-channel risks)")
    log.info("  - Popular choice for modern protocols")
    
    return log.summary()


if __name__ == "__main__":
    passed, failed = run()
    exit(0 if failed == 0 else 1)
