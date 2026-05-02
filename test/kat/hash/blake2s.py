# KAT/data/hash/blake2s.py
# Known Answer Tests for BLAKE2s (RFC 7693)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "BLAKE2s",
    "source": "RFC 7693 - The BLAKE2 Cryptographic Hash and MAC, Appendix B",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc7693",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "BLAKE2s is optimised for 8-to-32-bit platforms. Default output is 256 bits (32 bytes). Vectors from RFC 7693 Appendix B.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_len_bytes": 32,
        "output_hex": "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_len_bytes": 32,
        # RFC 7693 Appendix B
        "output_hex": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    },
    {
        "id": 3,
        "input_ascii": "The quick brown fox jumps over the lazy dog",
        "output_len_bytes": 32,
        "output_hex": "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
    },
    {
        "id": 4,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_len_bytes": 32,
        "output_hex": "6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189",
    },
    {"id": 5, "input_ascii": "a", "output_len_bytes": 32, "output_hex": "4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90"},
    {"id": 6, "input_ascii": "message digest", "output_len_bytes": 32, "output_hex": "fa10ab775acf89b7d3c8a6e823d586f6b67bdbac4ce207fe145b7d3ac25cd28c"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_len_bytes": 32, "output_hex": "bdf88eb1f86a0cdf0e840ba88fa118508369df186c7355b4b16cf79fa2710a12"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_len_bytes": 32, "output_hex": "c75439ea17e1de6fa4510c335dc3d3f343e6f9e1ce2773e25b4174f1df8b119b"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_len_bytes": 32, "output_hex": "fdaedb290a0d5af9870864fec2e090200989dc9cd53a3c092129e8535e8b4f66"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_len_bytes": 32, "output_hex": "94662583a600a12dff357c0a6f1b514a710ef0f587a38e8d2e4d7f67e9c81667"},
    {"id": 11, "input_ascii": "Hello, World!", "output_len_bytes": 32, "output_hex": "ec9db904d636ef61f1421b2ba47112a4fa6b8964fd4a0a514834455c21df7812"},
    {"id": 12, "input_ascii": "Python", "output_len_bytes": 32, "output_hex": "a397065c69cca78ba0d7ddfa03f54bfd1d95035f4f12039561cc3cd2fda7345b"},
    {"id": 13, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_len_bytes": 32, "output_hex": "8265e9235687e0db03e94d2827d2c44f5bcb2c9a51e3cd3198078500bc58e5f1"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_len_bytes": 32, "output_hex": "9d5b6436d9c8ae3b397f25afece0afe865b26748ae4986360bf2fd0ae0b28dd6"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_len_bytes": 32, "output_hex": "651d2f5f20952eacaea2fba2f2af2bcd633e511ea2d2e4c9ae2ac0d9ffb7b252"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_len_bytes": 32, "output_hex": "3ac477e27353f9019b81694afe60c8049403784f91a58288428ea318bfa82809"},
    {"id": 17, "input_ascii": A_LONG, "output_len_bytes": 32, "output_hex": "bec0c0e6cde5b67acb73b81f79a67a4079ae1c60dac9d2661af18e9f8b50dfa5"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_len_bytes": 32, "output_hex": "358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_len_bytes": 32, "output_hex": "3318ef7555850283d221269b40bf907e92020a8652105c4c4467777836a19d8e"},
    {"id": 20, "input_ascii": "1234567890", "output_len_bytes": 32, "output_hex": "369d270b22971d73d5c2ba4e956a9f02110e56917e11833e61b70e97334a6d20"},

]
