# KAT/data/modern/aes-gcm.py
# Known Answer Tests for AES-GCM (Galois/Counter Mode)

meta = {
    "group": "modern",
    "algorithm": "AES-GCM",
    "source": "NIST SP 800-38D (2007) Appendix B — GCM Test Cases",
    "source_ref": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES-GCM authenticated encryption. "
        "Case fields: key_bits, key_hex, iv_hex, aad_hex, plaintext_hex, "
        "ciphertext_hex, tag_hex (128-bit auth tag). "
        "Vectors from NIST SP 800-38D Appendix B (Test Cases 1, 2, 4). "
        "TC1 = empty PT+AAD, TC2 = 32-byte PT, TC4 = 60-byte PT with AAD."
    ),
}

cases = [
    # Test Case 1: AES-128, empty PT, empty AAD
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "00000000000000000000000000000000",
        "iv_hex": "000000000000000000000000",
        "aad_hex": "",
        "plaintext_hex": "",
        "ciphertext_hex": "",
        "tag_hex": "58e2fccefa7e3061367f1d57a4e7455a",
    },
    # Test Case 2: AES-128, 32 zero bytes PT
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "00000000000000000000000000000000",
        "iv_hex": "000000000000000000000000",
        "aad_hex": "",
        "plaintext_hex": "00000000000000000000000000000000" * 2,
        "ciphertext_hex": "0388dace60b6a392f328c2b971b2fe78" + "f795aaab494b5923f7fd89ff948bc1e0",
        "tag_hex": "ab6e47d42cec13bdf53a67b21257bddf",
    },
    # Test Case 4: AES-128, 60-byte PT, 20-byte AAD
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": "feffe9928665731c6d6a8f9467308308",
        "iv_hex": "cafebabefacedbaddecaf888",
        "aad_hex": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "plaintext_hex": (
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "ciphertext_hex": (
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985"
        ),
        "tag_hex": "5bc94fbc3221a5db94fae95ae7121a47",
    },
    # AES-256 GCM (computed via pycryptodome 3.23)
    {
        "id": 4,
        "key_bits": 256,
        "key_hex": "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "iv_hex": "cafebabefacedbaddecaf888",
        "aad_hex": "",
        "plaintext_hex": "d9313225f88406e5a55909c5aff5269a",
        "ciphertext_hex": "522dc1f099567d07f47f37a32a84427d",
        "tag_hex": "643a8cdcbfe5c0c97598a2bd2555d1aa",
    },
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '7346139595c0b41e497bbde365f42d0a',
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '120df4976cb7b979a064905f40ad9aad',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '221739b1b7db391a0ab404791312a7b7',
        "tag_hex": '9884bd92d5a56342688f62b8713503ee',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '221739b1b7db391a0ab404791312a7b7',
        "tag_hex": '1ad8742a852ba74a765384918fe359cc',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '221739b1b7db391a0ab404791312a7b71780a1792a696ea4ceea59f2d9187207',
        "tag_hex": '49c342744c8c1f4821fea69c815b78dd',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": '000000000000000000000000',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '221739b1b7db391a0ab404791312a7b71780a1792a696ea4ceea59f2d9187207',
        "tag_hex": '10d6fcd953ca09bcb86a607ea004efef',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": 'a945054aec8b8f4e4bdfe17f0557f09a',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": 'c80ee24815fc8229a2c0ccc3200e473d',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'e2b87954abb71e97432db7992e69b7cd',
        "tag_hex": '3a343817265584a417e4e7f7762e347f',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'e2b87954abb71e97432db7992e69b7cd',
        "tag_hex": 'b868f1af76db40ac093801de88f86e5d',
    },
    {
        "id": 15,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'e2b87954abb71e97432db7992e69b7cd2826b27345e81c39af5e79d733886380',
        "tag_hex": '6eaf17fe059ca49c24e6adb019d0df00',
    },
    {
        "id": 16,
        "key_bits": 128,
        "key_hex": '000102030405060708090a0b0c0d0e0f',
        "iv_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'e2b87954abb71e97432db7992e69b7cd2826b27345e81c39af5e79d733886380',
        "tag_hex": '37baa9531adab268bd726b52388f4832',
    },
    {
        "id": 17,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '494e385a4b3fafb713eaeca808626717',
    },
    {
        "id": 18,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000000000000000000000000',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '4b8d8c73bccee7258ff8068f22293006',
    },
    {
        "id": 19,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'b0c2ac69990dbbba6a7f3c37845932ec',
        "tag_hex": '581ed22141b0fd50b2f2de974855b387',
    },
    {
        "id": 20,
        "key_bits": 192,
        "key_hex": '000102030405060708090a0b0c0d0e0f1011121314151617',
        "iv_hex": '000000000000000000000000',
        "aad_hex": 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'b0c2ac69990dbbba6a7f3c37845932ec',
        "tag_hex": 'fbea19179558889b1bb34fa1d0156b05',
    },

]
