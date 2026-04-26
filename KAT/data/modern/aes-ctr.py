# KAT/data/modern/aes-ctr.py
# Known Answer Tests for AES-CTR (Counter Mode)

meta = {
    "group": "modern",
    "algorithm": "AES-CTR",
    "source": "NIST SP 800-38A (2001) Appendix F.5",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES in Counter mode. Counter block is a 128-bit big-endian integer "
        "incremented by 1 for each 16-byte block. "
        "Case fields: key_bits, key_hex, initial_counter_hex (16 bytes), "
        "plaintext_hex, ciphertext_hex. "
        "Vectors from NIST SP 800-38A Appendix F.5.1 (CTR-AES128)."
    ),
}

cases = [
    # F.5.1 CTR-AES128.Encrypt (4 blocks, counter starts at f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff)
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "initial_counter_hex": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "plaintext_hex": (
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
        "ciphertext_hex": (
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        ),
    },
    # Single-block test (counter = 1)
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "initial_counter_hex": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "874d6191b620e3261bef6864990db6ce",
    },
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'ad6085d5a9cfc4148672ff73d25bcf53',
    },
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '688cb160998cf71ef1f8eecee4675628',
    },
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": 'f669277124d3bf938ab4407bbbc28a96',
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": '303e1f7258c0c095c264c01947a4ef69',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '1887ad77bb802b88a046c3f216673a20',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'dd6b99c28bc31882d7ccd24f205ba35b',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '438e0fd3369c500fac807cfa7ffe7fe5',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": '85d937d04a8f2f09e450fc9883981a1a',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '0000000000000000ffffffffffffffff',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '526651e82418cd3e56ef7d32372c8338',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '0000000000000000ffffffffffffffff',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '978a655d145bfe3421656c8f01101a43',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '0000000000000000ffffffffffffffff',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '096ff34ca904b6b95a29c23a5eb5c6fd',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "nonce_hex": '0000000000000000ffffffffffffffff',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": 'cf38cb4fd517c9bf12f94258a2d3a302',
    },
    {
        "id": 15,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'faa3ef6032333ab42aaba8364b92812d',
    },
    {
        "id": 16,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '3f4fdbd5027009be5d21b98b7dae1856',
    },
    {
        "id": 17,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": 'a1aa4dc4bf2f4133266d173e220bc4e8',
    },
    {
        "id": 18,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000000',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": '67fd75c7c33c3e356ebd975cde6da117',
    },
    {
        "id": 19,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '228f86b8657f3021fad792b97bf1703d',
    },
    {
        "id": 20,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "nonce_hex": '00000000000000000000000000000001',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'e763b20d553c032b8d5d83044dcde946',
    },

]
