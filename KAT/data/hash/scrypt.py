# KAT/data/hash/scrypt.py
# Known Answer Tests for scrypt (memory-hard key derivation function)

meta = {
    "group": "hash",
    "algorithm": "scrypt",
    "source": "RFC 7914 Appendix B — The scrypt Password-Based Key Derivation Function",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc7914#appendix-B",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "scrypt is a memory-hard KDF designed by Colin Percival.  Parameters: "
        "N=CPU/memory cost (must be a power of 2), r=block size, p=parallelisation. "
        "Case fields: password_ascii, salt_ascii, N, r, p, dklen.  "
        "Vectors from RFC 7914 Appendix B (verified with Python hashlib.scrypt)."
    ),
}

cases = [
    {
        "id": 1,
        "password_ascii": "",
        "salt_ascii": "",
        "N": 16,
        "r": 1,
        "p": 1,
        "dklen": 64,
        "output_hex": (
            "77d6576238657b203b19ca42c18a0497"
            "f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17"
            "e8d3e0fb2e0d3628cf35e20c38d18906"
        ),
    },
    {
        "id": 2,
        "password_ascii": "password",
        "salt_ascii": "NaCl",
        "N": 1024,
        "r": 8,
        "p": 16,
        "dklen": 64,
        "output_hex": (
            "fdbabe1c9d3472007856e7190d01e9fe"
            "7c6ad7cbc8237830e77376634b373162"
            "2eaf30d92e22a3886ff109279d9830da"
            "c727afb94a83ee6d8360cbdfa2cc0640"
        ),
    },
    {
        "id": 3,
        "password_ascii": "pleaseletmein",
        "salt_ascii": "SodiumChloride",
        "N": 16384,
        "r": 8,
        "p": 1,
        "dklen": 64,
        "output_hex": (
            "7023bdcb3afd7348461c06cd81fd38eb"
            "fda8fbba904f8e3ea9b543f6545da1f2"
            "d5432955613f0fcf62d49705242a9af9"
            "e61e85dc0d651e40dfcf017b45575887"
        ),
    },
    {"id": 4, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "45133c3dfba48c82235df51a5349924110eee893752f0d4168d2e2aee5722d82"},
    {"id": 5, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 2, "p": 1, "dklen": 32, "output_hex": "3542784e3a6729fcad3e831acde065935863ac59ddc77ddc69043bb55f1a8837"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "salt", "N": 32, "r": 1, "p": 1, "dklen": 32, "output_hex": "ef197d6861e399d00d644d16558f9c7c837c245dadb9d65411020f3c8d98693d"},
    {"id": 7, "password_ascii": "abc", "salt_ascii": "NaCl", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "cf15be091e93858168184fe9d2b0b36049f78c6b01ff29b361b8071f650bddb8"},
    {"id": 8, "password_ascii": "abc", "salt_ascii": "NaCl", "N": 64, "r": 1, "p": 1, "dklen": 32, "output_hex": "5e7bec134fa4bfeee381b8f86a24e94d8d48a3be614e35b5b3809e8318a04169"},
    {"id": 9, "password_ascii": "", "salt_ascii": "salt", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "eec80a460eeaab62fe1630b19497e7ba6a1ff85f50807b9cfe52a9f192e5b60c"},
    {"id": 10, "password_ascii": "password", "salt_ascii": "", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "d33c6ec1818daaf728f55afadfeaa558b38efa81305b3521a7f12f4be097e84d"},
    {"id": 11, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 1, "p": 1, "dklen": 64, "output_hex": "45133c3dfba48c82235df51a5349924110eee893752f0d4168d2e2aee5722d8252ac44e09af64290dd64406ebfe74b5768d2e5ee88b55f78104306d5db5d8908"},
    {"id": 12, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 1, "p": 2, "dklen": 32, "output_hex": "d8daed18e86519e136e7b604855d9f22bdf9b29096706516b8f411740f003934"},
    {"id": 13, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 8, "p": 1, "dklen": 32, "output_hex": "f876178f94837d8721ec9d794a5e623283e9274a846dc0bfda4233a01d7ba68b"},
    {"id": 14, "password_ascii": "Password1!", "salt_ascii": "SodiumChloride", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "250ccfa9bd677a036f16dadfe7aab47aa4d31a3b609c862459e04215df2a5dbf"},
    {"id": 15, "password_ascii": "hello", "salt_ascii": "world", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "79277ba364150a536a16cd558fa5bedd3474ebe73496561963ca6d7e2474e981"},
    {"id": 16, "password_ascii": "test", "salt_ascii": "test", "N": 16, "r": 1, "p": 1, "dklen": 32, "output_hex": "bb1492f3b10a23e55421ac8a69dc962517fcdf037420db32ab1d0ddf28eee9e6"},
    {"id": 17, "password_ascii": "password", "salt_ascii": "salt", "N": 16, "r": 1, "p": 1, "dklen": 16, "output_hex": "45133c3dfba48c82235df51a53499241"},
    {"id": 18, "password_ascii": "password", "salt_ascii": "salt", "N": 256, "r": 1, "p": 1, "dklen": 32, "output_hex": "e904d229d6d0cc938b785e490f0cbb7e7f0bd69d9f7cad7a3b7c7a3530051d76"},
    {"id": 19, "password_ascii": "secret", "salt_ascii": "random", "N": 16, "r": 4, "p": 1, "dklen": 32, "output_hex": "992c3193dd5e0b3279e117d7b9b44f72a00f0df44dae5e27b8f7f632640a9608"},
    {"id": 20, "password_ascii": "admin", "salt_ascii": "somesalt", "N": 64, "r": 2, "p": 1, "dklen": 32, "output_hex": "693acf1efb44355a792562a0b67d8d03e0e3bdb6ed303d5d03f1fa5c126873f0"},

]
