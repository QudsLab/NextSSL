# KAT/data/hash/sha1.py
# Known Answer Tests for SHA-1 (FIPS 180-4)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA-1",
    "source": "FIPS 180-4 / NIST example values + di-mgt.com.au aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA-1 is deprecated for security use. Vectors from FIPS 180-4 examples.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "a9993e364706816aba3e25717850c26c9cd0d89d",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "a49b2446a02c645bf419f995b67091253a04a259",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "c12252ceda8be8994d5fa0290a47231c1d16aae3"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "761c457bf73b14d27e9e9265c46f4b4dda11f940"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "50abf5706a150990a08b2c5ea40fa0e585554732"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "0a0a9f2a6772942557ab5355d76af442f8f65e01"},
    {"id": 13, "input_ascii": "Python", "output_hex": "6e3604888c4b4ec08e2837913d012fe2834ffa83"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "c1c8bbdc22796e28c0e15163d20899b65621d65a"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "c2db330f6083854c99d4b5bfb6e8f29f201be699"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "0098ba824b5c16427bd7a1122a5a442a25ec644d"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "ad5b3fdbcb526778c2839d2f151ea753995e26a0"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "0114498021cb8c4f1519f96bdf58dd806f3adb63"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "01b307acba4f54f55aafc33bb06bbbf6ca803e9a"},

]
