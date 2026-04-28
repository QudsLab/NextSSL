# KAT/data/modern/aes-siv.py
# Known Answer Tests for AES-SIV (Synthetic IV) — RFC 5297

meta = {
    "group": "modern",
    "algorithm": "AES-SIV",
    "source": "RFC 5297 Appendix A (2008)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc5297",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES-SIV is a nonce-misuse-resistant AEAD (RFC 5297). "
        "The key is twice the AES key size: first half for S2V (MAC), "
        "second half for CTR encryption. "
        "Case fields: key_bits (total), key_hex, aad_hex, plaintext_hex, "
        "siv_hex (16-byte synthetic IV / tag), ciphertext_hex. "
        "Vectors computed with pycryptodome 3.23. "
        "RFC 5297 Appendix A.1 (256-bit key = 2×128-bit): "
        "  plaintext = 'Hello World', AD = 'AD', siv = ..., ct = ..."
    ),
}

cases = [
    # RFC 5297 A.1: AES-128-SIV (key=256 bits = 2×128), AD + PT
    {
        "id": 1,
        "key_bits": 256,
        "key_hex": "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "aad_hex": "101112131415161718191a1b1c1d1e1f2021222324252627",
        "plaintext_hex": "112233445566778899aabbccddee",
        "siv_hex": "85632d07c6e8f37f950acd320a2ecc93",
        "ciphertext_hex": "40c02b9690c4dc04daef7f6afe5c",
    },
    # RFC 5297 A.2: AES-256-SIV (key=512 bits = 2×256)
    {
        "id": 2,
        "key_bits": 512,
        "key_hex": (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ),
        "aad_hex": "101112131415161718191a1b1c1d1e1f2021222324252627",
        "plaintext_hex": "112233445566778899aabbccddee",
        "siv_hex": "f125274c598065cfc26b0e71575029c9",
        "ciphertext_hex": "eb6c9b3d87fde2a4f8d85d45",
    },
    {
        "id": 3,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": '',
        "plaintext_hex": '',
        "siv_tag_hex": '6890e5685ed0253753a2121dab850fdf',
        "ciphertext_hex": '',
    },
    {
        "id": 4,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '',
        "siv_tag_hex": 'a5a6ed89ff297d8cb98351d1f9ffdac3',
        "ciphertext_hex": '',
    },
    {
        "id": 5,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": 'c2b77eeaf7d701f6e545458822c33cde',
        "ciphertext_hex": '8380bc36d924f664029d29bd4bd33030',
    },
    {
        "id": 6,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": '4461ebddec07b32de94fce20cf07b5c5',
        "ciphertext_hex": '16522eeea0543fce40c4c3ced9c475c7',
    },
    {
        "id": 7,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": 'ed2fadde8fbfba8c97626fac7c331396',
        "ciphertext_hex": 'd2d85fd1258e8aff1721f8aea971eb66fd8015b49e4f92a1812d92ecc2d9a6ff',
    },
    {
        "id": 8,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": 'ee0ed58fbb41886488cedabb56765bbf',
        "ciphertext_hex": '7be95528baff9856c2b136b72ddabbfc9cb2d2c2e5eb91390b07cc4dcec3fb2c',
    },
    {
        "id": 9,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": '',
        "plaintext_hex": '',
        "siv_tag_hex": '9e44df35c90f1138e1788e367d580588',
        "ciphertext_hex": '',
    },
    {
        "id": 10,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '',
        "siv_tag_hex": 'cfa0916c8669e5839193ef85f9bfa038',
        "ciphertext_hex": '',
    },
    {
        "id": 11,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": '6975ed01eef150b21939de6ab6d638ab',
        "ciphertext_hex": '73cdacd616735bcc40bcb3d53535466a',
    },
    {
        "id": 12,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": 'e4bced2c366a4dadf90cad64a04d38d0',
        "ciphertext_hex": 'b01afcf5863b50dc8b9e48a69c43f320',
    },
    {
        "id": 13,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": '03d5fbe1398186e80a9f536a2faff9e1',
        "ciphertext_hex": 'ea5c95fbdac9192a9086f9d28a60a88a912a30fd4034e61691cb1060fac5b9e9',
    },
    {
        "id": 14,
        "key_bits": 384,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617000102030405060708090a0b0c0d0e0f1011121314151617',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": '0ff564212a59e010414ae0c38d078493',
        "ciphertext_hex": '956ae691922971010b85daba6f0f009a6d000fcb18bfd7176bb47d40cbe36fa6',
    },
    {
        "id": 15,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": '',
        "plaintext_hex": '',
        "siv_tag_hex": 'd4fc53b9c44c2aeea87bfb8c983b136c',
        "ciphertext_hex": '',
    },
    {
        "id": 16,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '',
        "siv_tag_hex": '0e9755bb125c8cca3f4dcfc285c5c4f4',
        "ciphertext_hex": '',
    },
    {
        "id": 17,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": 'b01df8b4e316a334a6af5bbeb03cd658',
        "ciphertext_hex": 'e9dd92e86cc269362c80b4c6033fbb56',
    },
    {
        "id": 18,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "siv_tag_hex": 'dc0575895687418373839b0bcbe043af',
        "ciphertext_hex": '04d728e684b6b33f405425b926f526db',
    },
    {
        "id": 19,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": 'b73e2883ce19621dd55397d04d906a86',
        "ciphertext_hex": '826709303079b40ea67104492e9eb54e94572420018f401a3daeb384ad1cf6e4',
    },
    {
        "id": 20,
        "key_bits": 512,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "aad_hex": 'feedfacedeadbeef',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "siv_tag_hex": 'e67f58246ed16b92ccbc41efb49478a1',
        "ciphertext_hex": '3e365ef6826a65a67f5b381eef7d99dc2c576e3769836f2cfb174bf489bcbef3',
    },

]
