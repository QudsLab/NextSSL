# KAT/data/modern/aes-ofb.py
# Known Answer Tests for AES-OFB (Output Feedback Mode)

meta = {
    "group": "modern",
    "algorithm": "AES-OFB",
    "source": "NIST SP 800-38A (2001) Appendix F.4",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES in Output Feedback mode. "
        "Case fields: key_bits, key_hex, iv_hex, plaintext_hex, ciphertext_hex. "
        "Vectors from NIST SP 800-38A Appendix F.4.1 (OFB-AES128)."
    ),
}

cases = [
    # F.4.1 OFB-AES128.Encrypt (4 blocks combined)
    {
        "id": 1,
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
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e"
        ),
    },
    # Single block
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "000102030405060708090a0b0c0d0e0f",
        "plaintext_hex": "6bc1bee22e409f96e93d7e117393172a",
        "ciphertext_hex": "3b3fd92eb72dad20333449f8e83cfb4a",
    },
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '6155b5576f2e6fd318feea49b5c0fd70',
    },
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'a4b981e25f6d5cd96f74fbf483fc640b',
    },
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '3a5c17f3e232145414385541dc59b8b5',
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": 'fc0b2ff09e216b525ce8d523203fdd4a',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": '0a940bb5416ef045f1c39458c653ea5a',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'f56bf44abe910fba0e3c6ba739ac15a5',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '5785a1d0e0471db58deadc887dc3ac39',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '92699565d0042ebffa60cd354bff3542',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '0c8c03746d5b6632812c6380145ae9fc',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": 'cadb3b7711481934c9fce3e2e83c8c03',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": '3c441f32ce07822364d7a2990e50bb13',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'c3bbe0cd31f87ddc9b285d66f1af44ec',
    },
    {
        "id": 15,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '6ba1011c68c3d42e336187b76c613784',
    },
    {
        "id": 16,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'ae4d35a95880e72444eb960a5a5daeff',
    },
    {
        "id": 17,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '30c81c46a35ce411e5fbc1191a0a52ef',
        "ciphertext_hex": '30a8a3b8e5dfafa93fa738bf05f87241',
    },
    {
        "id": 18,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'f69f2445df4f9b17ad2b417be66c3710',
        "ciphertext_hex": 'f6ff9bbb99ccd0af7777b8ddf99e17be',
    },
    {
        "id": 19,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": '0060bffe46834bb8da5cf9a61ff220ae',
    },
    {
        "id": 20,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'ff9f4001b97cb44725a30659e00ddf51',
    },

]
