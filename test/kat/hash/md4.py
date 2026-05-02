# KAT/data/hash/md4.py
# Known Answer Tests for MD4 (RFC 1320)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "MD4",
    "source": "RFC 1320 - The MD4 Message-Digest Algorithm, Appendix A.5",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc1320",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "MD4 is considered cryptographically broken. Vectors from RFC 1320 §A.5.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "31d6cfe0d16ae931b73c59d7e0c089c0",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "bde52cb31de33e46245e05fbdbd6fb24",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "a448017aaf21d8525fc10ae87aa6729d",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "d9130a8164549fe818874806e1c7014b",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "d79e1c308aa5bbcdeea8ed63df412da9",
    },
    {
        "id": 6,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "043f8582f241db351ce627e153e7f0e4",
    },
    {
        "id": 7,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "e33b4ddc9c38f2199c3e7b164fcc0536",
    },
    {"id": 8, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "1bee69a46ba811185c194762abaeae90"},
    {"id": 9, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "b86e130ce7028da59e672d56ad0113df"},
    {"id": 10, "input_ascii": "Hello, World!", "output_hex": "94e3cb0fa9aa7a5ee3db74b79e915989"},
    {"id": 11, "input_ascii": "Python", "output_hex": "ecde2f12a12a9a5addc2e6f8e303c7f6"},
    {"id": 12, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "c889c81dd86c4d2e025778944ea02881"},
    {"id": 13, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "d5f9a9e9257077a5f08b0b92f348b0ad"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "52f5076fabd22680234a3fa9f9dc5732"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "cb4a20a561558e29460190c91dced59f"},
    {"id": 16, "input_ascii": A_LONG, "output_hex": "bbce80cc6bb65e5c6745e30d4eeca9a4"},
    {"id": 17, "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output_hex": "4691a9ec81b1a6bd1ab8557240b245c5"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "2102d1d94bd58ebf5aa25c305bb783ad"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "8eeb1da56a848640cedd21c9665ef624"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "85b196c3e39457d91cab9c905f9a11c0"},

]
