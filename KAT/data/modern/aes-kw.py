# KAT/data/modern/aes-kw.py
# Known Answer Tests for AES Key Wrap (RFC 3394 / NIST SP 800-38F)

meta = {
    "group": "modern",
    "algorithm": "AES-KW",
    "source": "RFC 3394 §2.2 / NIST SP 800-38F Appendix B (2012)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc3394",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES Key Wrap (RFC 3394 / NIST SP 800-38F) for wrapping key material. "
        "Case fields: kek_bits, kek_hex (key-encryption key), "
        "plaintext_key_hex (key to wrap), wrapped_key_hex (8 bytes longer). "
        "Vectors from RFC 3394 §2.2 test vectors. "
        "Computed with pyca/cryptography library."
    ),
}

cases = [
    # RFC 3394 §2.2.1: 128-bit KEK, 128-bit key
    {
        "id": 1,
        "kek_bits": 128,
        "kek_hex": "000102030405060708090A0B0C0D0E0F",
        "plaintext_key_hex": "00112233445566778899AABBCCDDEEFF",
        "wrapped_key_hex": "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
    },
    # RFC 3394 §2.2.2: 192-bit KEK, 128-bit key
    {
        "id": 2,
        "kek_bits": 192,
        "kek_hex": "000102030405060708090A0B0C0D0E0F1011121314151617",
        "plaintext_key_hex": "00112233445566778899AABBCCDDEEFF",
        "wrapped_key_hex": "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
    },
    # RFC 3394 §2.2.3: 256-bit KEK, 128-bit key
    {
        "id": 3,
        "kek_bits": 256,
        "kek_hex": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "plaintext_key_hex": "00112233445566778899AABBCCDDEEFF",
        "wrapped_key_hex": "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7",
    },
    # RFC 3394 §2.2.6: 256-bit KEK, 256-bit key
    {
        "id": 4,
        "kek_bits": 256,
        "kek_hex": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "plaintext_key_hex": "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "wrapped_key_hex": "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
    },
    {
        "id": 5,
        "kek_bits": 128,
        "kek_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5',
    },
    {
        "id": 6,
        "kek_bits": 128,
        "kek_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '47a5101bea68c9c05043f5a072c451e716238c41c427e30d0e315c277c2e4cd7',
    },
    {
        "id": 7,
        "kek_bits": 192,
        "kek_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d',
    },
    {
        "id": 8,
        "kek_bits": 192,
        "kek_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '66ed7720434357f471e09b877fda5ba357169a66d56f62ea7747b4a61e4cef5b',
    },
    {
        "id": 9,
        "kek_bits": 256,
        "kek_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7',
    },
    {
        "id": 10,
        "kek_bits": 256,
        "kek_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '3e7aef8a04f35ebeb26440c8e4660d723f5bfc7ac4c017d627cd5e7c1a040339',
    },
    {
        "id": 11,
        "kek_bits": 256,
        "kek_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f',
        "wrapped_key_hex": '28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21',
    },
    {
        "id": 12,
        "kek_bits": 128,
        "kek_hex": '0000000000000000000000000000000f',
        "plaintext_key_hex": '00000000000000000000000000000001',
        "wrapped_key_hex": '81b9f734aedae8c36596f2bb006904ceec4190dd90b72d77',
    },
    {
        "id": 13,
        "kek_bits": 128,
        "kek_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_key_hex": 'ffffffffffffffffffffffffffffffff',
        "wrapped_key_hex": 'af676af9fd2383d546f73ac637eb93f690f285401e053318',
    },
    {
        "id": 14,
        "kek_bits": 256,
        "kek_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_key_hex": '01010101010101010101010101010101',
        "wrapped_key_hex": '5ffa2997f64f1fdb6a06c94d025d01d4c4ad38cd9bc18ebd',
    },

    {
        "id": 15,
        "kek_bits": 128,
        "kek_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5',
    },
    {
        "id": 16,
        "kek_bits": 128,
        "kek_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '47a5101bea68c9c05043f5a072c451e716238c41c427e30d0e315c277c2e4cd7',
    },
    {
        "id": 17,
        "kek_bits": 192,
        "kek_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d',
    },
    {
        "id": 18,
        "kek_bits": 192,
        "kek_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '66ed7720434357f471e09b877fda5ba357169a66d56f62ea7747b4a61e4cef5b',
    },
    {
        "id": 19,
        "kek_bits": 256,
        "kek_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff',
        "wrapped_key_hex": '64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7',
    },
    {
        "id": 20,
        "kek_bits": 256,
        "kek_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "plaintext_key_hex": '00112233445566778899aabbccddeeff0011223344556677',
        "wrapped_key_hex": '3e7aef8a04f35ebeb26440c8e4660d723f5bfc7ac4c017d627cd5e7c1a040339',
    },

]
