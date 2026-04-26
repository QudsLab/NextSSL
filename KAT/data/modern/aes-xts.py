# KAT/data/modern/aes-xts.py
# Known Answer Tests for AES-XTS (XEX-based Tweaked CodeBook, IEEE 1619-2007)

meta = {
    "group": "modern",
    "algorithm": "AES-XTS",
    "source": "IEEE 1619-2007 / NIST SP 800-38E — Test Vectors",
    "source_ref": "https://ieeexplore.ieee.org/document/4493450",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES-XTS for disk encryption (IEEE 1619-2007 / NIST SP 800-38E). "
        "The key is key1||key2 (each half equal to AES key size); "
        "key1 and key2 MUST be different. "
        "Case fields: key_bits (per half), combined_key_hex (key1||key2), "
        "tweak_hex (16-byte sector/block address), plaintext_hex, ciphertext_hex. "
        "Vectors from IEEE 1619-2007 test cases. "
        "Computed with pyca/cryptography library."
    ),
}

cases = [
    # IEEE 1619-2007 Vector 2: key1=11..11, key2=22..22, tweak=33..33, data=44..44
    {
        "id": 1,
        "key_bits": 128,
        "combined_key_hex": "11111111111111111111111111111111" + "22222222222222222222222222222222",
        "tweak_hex": "33333333330000000000000000000000",
        "plaintext_hex": "4444444444444444444444444444444444444444444444444444444444444444",
        "ciphertext_hex": "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
    },
    # IEEE 1619-2007 Vector 3
    {
        "id": 2,
        "key_bits": 128,
        "combined_key_hex": "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" + "22222222222222222222222222222222",
        "tweak_hex": "33333333330000000000000000000000",
        "plaintext_hex": "4444444444444444444444444444444444444444444444444444444444444444",
        "ciphertext_hex": "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
    },
    # IEEE 1619-2007 Vector 4: key from SP 800-38E
    {
        "id": 3,
        "key_bits": 128,
        "combined_key_hex": "2718281828459045235360287471352631415926535897932384626433832795",
        "tweak_hex": "00000000000000000000000000000000",
        "plaintext_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ciphertext_hex": "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c",
    },
    {
        "id": 4,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '49a680e57ed2fd3c94e8c93441bddd2e',
    },
    {
        "id": 5,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'de9dcc1b225f3793ba7e7fd78455fc62',
    },
    {
        "id": 6,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": 'ef646e3a7a5b9cb872a91897e9d8d0e0',
    },
    {
        "id": 7,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '5e24d0fe31dbd3e740722b3575c33065',
    },
    {
        "id": 8,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '49a680e57ed2fd3c94e8c93441bddd2e422f9cf28f51ad3ed85dcfda04233332',
    },
    {
        "id": 9,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'ef646e3a7a5b9cb872a91897e9d8d0e0febe3e235fc6e41bb12f579698e4ce5b',
    },
    {
        "id": 10,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'aa42f01d4d9436c7c87bf4eee6d84f71',
    },
    {
        "id": 11,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'fa7847997f30d93048415dc173882bcb',
    },
    {
        "id": 12,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": 'e7afbdc762349a8f47b8d2df3673cd25',
    },
    {
        "id": 13,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'b37c4566344df5ed87e15d387523b63c',
    },
    {
        "id": 14,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'aa42f01d4d9436c7c87bf4eee6d84f713f55cff5d610e9cf85d2a62764a810ca',
    },
    {
        "id": 15,
        "key_bits": 512,
        "key_hex": '0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f00f0e0d0c0b0a09080706050403020100',
        "tweak_hex": 'ffffffffffffffffffffffffffffffff',
        "plaintext_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'e7afbdc762349a8f47b8d2df3673cd25bcfdc169c4a4a7876864bb7d531f4677',
    },

    {
        "id": 16,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '6050a8fd71c8d6f692d714e8b9279fd5',
    },
    {
        "id": 17,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '92a385934fd0af5670aac62f8c9d9a9a',
    },
    {
        "id": 18,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '00000000000000000000000000000000',
        "ciphertext_hex": '9b6e5e888f5930fa325f4718c578d493',
    },
    {
        "id": 19,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": 'ffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'e18f8bff24dadc38c175eb2508b04638',
    },
    {
        "id": 20,
        "key_bits": 256,
        "key_hex": '000102030405060708090a0b0c0d0e0ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
        "tweak_hex": '000102030405060708090a0b0c0d0e0f',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '6050a8fd71c8d6f692d714e8b9279fd5533bf16e2b638921c8f856dad4649602',
    },

]
