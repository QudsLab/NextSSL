# KAT/data/modern/aes-cmac.py
# Known Answer Tests for AES-CMAC (Cipher-based MAC)

meta = {
    "group": "modern",
    "algorithm": "AES-CMAC",
    "source": "NIST SP 800-38B Appendix D (2005)",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "CMAC (Cipher-based MAC) using AES-128 (NIST SP 800-38B). "
        "Case fields: key_bits, key_hex, message_hex, tag_hex (16 bytes). "
        "Vectors from NIST SP 800-38B Appendix D: "
        "D.1 AES-128 examples 1–4 with lengths 0, 16, 40, 64 bytes. "
        "Computed with pycryptodome 3.23."
    ),
}

cases = [
    # D.1 Example 1: empty message
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "message_hex": "",
        "tag_hex": "bb1d6929e95937287fa37d129b756746",
    },
    # D.1 Example 2: 16 bytes
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "message_hex": "6bc1bee22e409f96e93d7e117393172a",
        "tag_hex": "070a16b46b4d4144f79bdd9dd04a287c",
    },
    # D.1 Example 3: 40 bytes
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "message_hex": (
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411"
        ),
        "tag_hex": "dfa66747de9ae63030ca32611497c827",
    },
    # D.1 Example 4: 64 bytes
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "message_hex": (
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
        "tag_hex": "51f0bebf7e3b9d92fc49741779363cfe",
    },
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '',
        "mac_hex": '97dd6e5a882cbd564c39ae7d1c5a31aa',
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": 'd0bc5bb4d6f60d5b17b7bf794b45436d',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "mac_hex": '2922def995eb803b1478f76bc7ad659c',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '4a64b0aa4bffbaab3c1fc5f2d974de66',
    },
    {
        "id": 9,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "message_hex": '',
        "mac_hex": 'ec12390ea0a7ed15d9d37a6eca1fc990',
    },
    {
        "id": 10,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '002ffdcd32f620b60d0087178c83d16c',
    },
    {
        "id": 11,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "message_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "mac_hex": '65eda897e7950132b8aeb65e68e82488',
    },
    {
        "id": 12,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '6106f3946f8f963a413513d52a19a5e6',
    },
    {
        "id": 13,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "message_hex": '',
        "mac_hex": '6bf0a293d8cba0101f0089727691b7fb',
    },
    {
        "id": 14,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '9553f77c77b44a0a775e4efff8831308',
    },
    {
        "id": 15,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "mac_hex": '351799b0fdb15b4798e347efa3b4e189',
    },
    {
        "id": 16,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '66ffce2a6ef60b0f1491425a63859bb4',
    },

    {
        "id": 17,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '',
        "mac_hex": '97dd6e5a882cbd564c39ae7d1c5a31aa',
    },
    {
        "id": 18,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": 'd0bc5bb4d6f60d5b17b7bf794b45436d',
    },
    {
        "id": 19,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "mac_hex": '2922def995eb803b1478f76bc7ad659c',
    },
    {
        "id": 20,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "mac_hex": '4a64b0aa4bffbaab3c1fc5f2d974de66',
    },

]
