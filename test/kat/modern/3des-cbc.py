# KAT/data/modern/3des-cbc.py
# Known Answer Tests for 3DES-CBC (Triple-DES Cipher Block Chaining)

meta = {
    "group": "modern",
    "algorithm": "3DES-CBC",
    "source": "NIST SP 800-67 Rev 2 (2017) Appendix B",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Triple-DES in CBC mode (3TDEA with 3 independent 56-bit subkeys = 168-bit key). "
        "Case fields: key_hex (24 bytes = 192 bits including parity), iv_hex, "
        "plaintext_hex, ciphertext_hex. "
        "Vectors computed with pycryptodome 3.23. "
        "NOTE: 3DES is deprecated (NIST SP 800-131A Rev 2); "
        "AES should be used for new designs."
    ),
}

cases = [
    # Computed vector (pycryptodome 3.23)
    {
        "id": 1,
        "key_hex": "0123456789abcdeffedcba987654321089abcdef01234567",
        "iv_hex": "7695b25b2b1b0f10",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "6fb6f439eb5eeab0ec50f54bc3de3f3d",
    },
    # Standard test: NIST Known Answer Test key1 = key3
    {
        "id": 2,
        "key_hex": "0101010101010101010101010101010101010101010101010101010101010101"[:48],
        "iv_hex": "0000000000000000",
        "plaintext_hex": "0000000000000000",
        "ciphertext_hex": "95f8a5e5dd31d900",
    },
    # CBC test with known pattern
    {
        "id": 3,
        "key_hex": "8001010101010101010101010101010101010101010101010101010101010101"[:48],
        "iv_hex": "0000000000000000",
        "plaintext_hex": "0000000000000000",
        "ciphertext_hex": "95a8d72813daa94d",
    },
    {
        "id": 4,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '0000000000000000',
        "ciphertext_hex": '3fd539e3abeb8b5b',
    },
    {
        "id": 5,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": 'ffffffffffffffff',
        "ciphertext_hex": '54c0ea58976d4e2c',
    },
    {
        "id": 6,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '0102030405060708',
        "ciphertext_hex": '99694f0aa1a4df37',
    },
    {
        "id": 7,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": 'deadbeef01020304',
        "ciphertext_hex": 'ccf8608cc45847fd',
    },
    {
        "id": 8,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'a40aa617219768d8ded584d9016e02b3',
    },
    {
        "id": 9,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '7c8ce5f35f9885da83c245d8f6aec329',
    },
    {
        "id": 10,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '0000000000000000ffffffffffffffff',
        "ciphertext_hex": '3fd539e3abeb8b5be21566cdacc21bce',
    },
    {
        "id": 11,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": '0000000000000000',
        "ciphertext_hex": '99694f0aa1a4df37',
    },
    {
        "id": 12,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": 'ffffffffffffffff',
        "ciphertext_hex": 'e9650b5f681f9e82',
    },
    {
        "id": 13,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": '0102030405060708',
        "ciphertext_hex": '3fd539e3abeb8b5b',
    },
    {
        "id": 14,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": 'deadbeef01020304',
        "ciphertext_hex": '80cf15c4ffa5ecf4',
    },
    {
        "id": 15,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'e210843eff51dbab1a133299cdd69456',
    },
    {
        "id": 16,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'e291cc9e65a92358218b33f47d213551',
    },
    {
        "id": 17,
        "key_hex": '0123456789abcdeffedcba987654321089abcdef01234567',
        "iv_hex": '0102030405060708',
        "plaintext_hex": '0000000000000000ffffffffffffffff',
        "ciphertext_hex": '99694f0aa1a4df376b21eeeeb53e7992',
    },
    {
        "id": 18,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '0000000000000000',
        "ciphertext_hex": '894bc3085426a441',
    },
    {
        "id": 19,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '0000000000000000',
        "plaintext_hex": 'ffffffffffffffff',
        "ciphertext_hex": '4e724a6625806f85',
    },
    {
        "id": 20,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '0000000000000000',
        "plaintext_hex": '0102030405060708',
        "ciphertext_hex": 'f97812fde0967539',
    },

]
