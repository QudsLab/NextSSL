# KAT/data/hash/blake3.py
# Known Answer Tests for BLAKE3

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "BLAKE3",
    "source": "BLAKE3 official test vectors (github.com/BLAKE3-team/BLAKE3)",
    "source_ref": "https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "BLAKE3 default output is 256 bits (32 bytes). "
        "Official test vectors use a repeating input byte sequence: 0x00, 0x01, ..., 0xFA, 0x00, 0x01, ... "
        "output_hex here is the first 32 bytes (256-bit default digest) of the extended output. "
        "input_hex encodes this pattern for the given length."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        # input_len=0, empty input
        "output_hex": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    },
    {
        "id": 2,
        # input_len=1, input = 0x00
        "input_hex": "00",
        "output_hex": "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    },
    {
        "id": 3,
        # input_len=8, input = 0x00..0x07
        "input_hex": "0001020304050607",
        "output_hex": "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
    },
    {
        "id": 4,
        # input_len=63, input = 0x00..0x3E
        "input_hex": (
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e"
        ),
        "output_hex": "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    },
    {"id": 5, "input_ascii": "a", "output_hex": "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f"},
    {"id": 6, "input_ascii": "abc", "output_hex": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"},
    {"id": 7, "input_ascii": "message digest", "output_hex": "7bc2a2eeb95ddbf9b7ecf6adcb76b453091c58dc43955e1d9482b1942f08d19b"},
    {"id": 8, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "2468eec8894acfb4e4df3a51ea916ba115d48268287754290aae8e9e6228e85f"},
    {"id": 9, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "8bee3200baa9f3a1acd279f049f914f110e730555ff15109bd59cdd73895e239"},
    {"id": 10, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "f263acf51621980b9c8de5da4a17d314984e05abe4a21cc83a07fe3e1e366dd1"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a"},
    {"id": 12, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "dcfa146b91a62f797fd3f82c7fb948dee6b5c14711ecfad94587938e200c1f43"},
    {"id": 13, "input_ascii": "Hello, World!", "output_hex": "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8"},
    {"id": 14, "input_ascii": "Python", "output_hex": "4df8ba384a198aac8b97b40b7339d57b05d81fd91214f76bbb95ee0022216b6b"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "8e0494b8aa1fa7fc245b4de5ecfb343f35550e6cc3c051e1e872c4a0a4105f83"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "86dd7cd514f2b1f6aaa34688ead22746f453e9d9ddeeca1ef124477507aefc9f"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "472c51290d607f100d2036fdcedd7590bba245e9adeb21364a063b7bb4ca81c7"},
    {"id": 18, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "0753df896d00f20c247f7e8c8977bb84d42f57532a5cc30d8f2ea035c9ce5757"},
    {"id": 19, "input_ascii": A_LONG, "output_hex": "616f575a1b58d4c9797d4217b9730ae5e6eb319d76edef6549b46f4efe31ff8b"},
    {"id": 20, "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output_hex": "c19012cc2aaf0dc3d8e5c45a1b79114d2df42abb2a410bf54be09e891af06ff8"},

]
