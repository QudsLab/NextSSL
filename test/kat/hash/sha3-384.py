# KAT/data/hash/sha3-384.py
# Known Answer Tests for SHA3-384 (FIPS 202)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA3-384",
    "source": "FIPS 202 / di-mgt.com.au SHA test vector aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA3-384 is NIST FIPS 202 standard (Keccak with SHA-3 domain separation). 48-byte output.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "e414797403c7d01ab64b41e90df4165d59b7f147e4292ba2da336acba242fd651949eb1cfff7e9012e134b40981842e1"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "aa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe"},
    {"id": 13, "input_ascii": "Python", "output_hex": "ad982435db4f702410110a857cf6c11ead9e38b2fec946363b0705ec2b216b2d811ce85a639ba8e7eab2a58ed3e7d883"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "2b1500b974c6cd2c595d491edf61043bca0b405e6e5261da9ec01b30a03cf32dae3360509c2002dcfea4926746df3108"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "2777b6ee7309657e7feb159e001af7f5a69a24fe6aedab05ef575cb260b5ca9d4dee4fc9a68dec0e6f820b88a6369a04"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "2d811f3045bb42b43b8ecadd41ccc1391be8ad805ac626ed4ecbaa6c538032b832437baf3b89e8e56e83f47e9183045d"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "462624563c7683b8233d455c8eea10f4fbd3bacb86f3f26f74ed65754cb57935b7624f01d17f855e8b17cb0be62aaee6"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "4c3578fa9e31872b06a2f3cdbd91470591f963fa6c38d76c4754970b60a1d9c77fc2adf2fdfef804ea77ef6872dd8616"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "6fdddab7d670f202629531c1a51b32ca30696d0af4dd5b0fbb5f82c0aba5e505110455f37d7ef73950c2bb0495a38f56"},

]
