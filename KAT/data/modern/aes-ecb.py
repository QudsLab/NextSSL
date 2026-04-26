# KAT/data/modern/aes-ecb.py
# Known Answer Tests for AES-ECB (Electronic Codebook Mode)

meta = {
    "group": "modern",
    "algorithm": "AES-ECB",
    "source": "NIST SP 800-38A (2001) Appendix F.1",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES in Electronic Codebook mode — each block encrypted independently. "
        "Case fields: key_bits, key_hex, plaintext_hex, ciphertext_hex. "
        "Vectors from NIST SP 800-38A Appendix F.1."
    ),
}

cases = [
    # F.1.1 ECB-AES128.Encrypt
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "3ad77bb40d7a3660a89ecaf32466ef97",
    },
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "plaintext_hex": "ae2d8a571e03ac9c9eb76fac45af8e51",
        "ciphertext_hex": "f5d3d58503b9699de785895a96fdbaaf",
    },
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "plaintext_hex": "30c81c46a35ce411e5fbc1191a0a52ef",
        "ciphertext_hex": "43b1cd7f598ece23881b00e3ed030688",
    },
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "plaintext_hex": "f69f2445df4f9b17ad2b417be66c3710",
        "ciphertext_hex": "7b0c785e27e8ad3f8223207104725dd4",
    },
    # F.1.5 ECB-AES256.Encrypt
    {
        "id": 5,
        "key_bits": 256,
        "key_hex": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "f3eed1bdb5d2a03c064b5a7e3db181f8",
    },
    {
        "id": 6,
        "key_bits": 256,
        "key_hex": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "plaintext_hex": "ae2d8a571e03ac9c9eb76fac45af8e51",
        "ciphertext_hex": "591ccb10d410ed26dc5ba74a31362870",
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '47c58d5e21caaf840d015b7d9b910981',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '5c051c31e4a777747c38eba4dc62e073',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '8c5c6e72e453a92a446ce7d78c221eac',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": 'ae4ea8f78fb85884cb77dc4d11e98392',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": 'c6a13b37878f5b826f4f8162a1c8d879',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '3c441f32ce07822364d7a2990e50bb13',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '0102030405060708090a0b0c0d0e0f10',
        "ciphertext_hex": '0892085605be8f349f584af993df11f8',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'deadbeefcafebabe0102030405060708',
        "ciphertext_hex": '8078400781930600a38fbab2d7225d56',
    },
    {
        "id": 15,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'aabbccddeeff00112233445566778899',
        "ciphertext_hex": 'a0ccf098a39dd26541068a6e945f2938',
    },
    {
        "id": 16,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '47c58d5e21caaf840d015b7d9b910981',
    },
    {
        "id": 17,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": 'c6a13b37878f5b826f4f8162a1c8d879',
    },
    {
        "id": 18,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '3c441f32ce07822364d7a2990e50bb13',
    },
    {
        "id": 19,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '1b58bc54cd0cb07a1c91b8d25339da3b',
    },
    {
        "id": 20,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'aafe440da3d1c3367aa41066615048d3',
    },

]
