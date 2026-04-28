# KAT/data/modern/aes-cbc.py
# Known Answer Tests for AES-CBC (Cipher Block Chaining)

meta = {
    "group": "modern",
    "algorithm": "AES-CBC",
    "source": "NIST SP 800-38A (2001) Appendix F.2",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES in Cipher Block Chaining mode. "
        "Case fields: key_bits, key_hex, iv_hex, plaintext_hex, ciphertext_hex. "
        "For multi-block cases, plaintext/ciphertext are concatenated blocks. "
        "Vectors from NIST SP 800-38A Appendix F.2.1 (AES-128-CBC)."
    ),
}

cases = [
    # F.2.1 CBC-AES128.Encrypt, blocks processed independently below
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "000102030405060708090a0b0c0d0e0f",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "7649abac8119b246cee98e9b12e9197d",
    },
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "7649abac8119b246cee98e9b12e9197d",
        "plaintext_hex": "ae2d8a571e03ac9c9eb76fac45af8e51",
        "ciphertext_hex": "5086cb9b507219ee95db113a917678b2",
    },
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "5086cb9b507219ee95db113a917678b2",
        "plaintext_hex": "30c81c46a35ce411e5fbc1191a0a52ef",
        "ciphertext_hex": "73bed6b8e3c1743b7116e69e22229516",
    },
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "73bed6b8e3c1743b7116e69e22229516",
        "plaintext_hex": "f69f2445df4f9b17ad2b417be66c3710",
        "ciphertext_hex": "3ff1caa1681fac09120eca307586e1a7",
    },
    # F.2.1 as 4-block combined (same key, original IV, all 4 plaintexts)
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "000102030405060708090a0b0c0d0e0f",
        "plaintext_hex": (
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
        "ciphertext_hex": (
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        ),
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'e4ef93eb8ef9a7424709f8eaa953450e',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '2a7dee46cc6b25665ab675784bd69925',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": 'd81a30fd2cacd757983e7504da9ae2e9',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": '934d2dafba4574c7a2b73489e8a54ccc',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": '0a940bb5416ef045f1c39458c653ea5a',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'b384eca4b39915a723f582e920854459',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '0102030405060708090a0b0c0d0e0f10',
        "ciphertext_hex": '5cfa70135ea72d7f311d3d57da1553a4',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'deadbeefcafebabe0102030405060708',
        "ciphertext_hex": 'b1052a77c48c41adad8c71cb12b0fc3d',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'aabbccddeeff00112233445566778899',
        "ciphertext_hex": '9d7ec0c708c27cb998c154121c4df983',
    },
    {
        "id": 15,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'e4ef93eb8ef9a7424709f8eaa953450e68573316a3d7fa7af03c6a350e53c2ba',
    },
    {
        "id": 16,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '0a940bb5416ef045f1c39458c653ea5aaee71ea541d7ae4beb60becc593fb663',
    },
    {
        "id": 17,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'b384eca4b39915a723f582e9208544594f12b2bbf75b557de8a98c23ab89b381',
    },
    {
        "id": 18,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '976d422e5a2f86ff863ac5dd5b98f27a',
    },
    {
        "id": 19,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '18957ca639c7edefd92f659279a39a8e',
    },
    {
        "id": 20,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '26a7bb68657213b83bb5314a49370cc7',
    },

]
