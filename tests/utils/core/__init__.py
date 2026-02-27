"""Core cryptography tests - 38 algorithms across 6 categories.

Test modules:
- test_aes_modes.py: 9 modes (CBC, CFB, OFB, CTR, ECB, XTS, KW, FPE-FF1, FPE-FF3)
- test_aes_aead.py: 7 AEAD modes (GCM, CCM, OCB, EAX, GCM-SIV, SIV, Poly1305)
- test_stream_aead.py: 1 algorithm (ChaCha20-Poly1305)
- test_ecc.py: 6 curves (Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2)
- test_macs.py: 9 MAC algorithms
- test_kdf.py: 6 KDF functions
"""
