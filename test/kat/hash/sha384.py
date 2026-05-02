# KAT/data/hash/sha384.py
# Known Answer Tests for SHA-384 (FIPS 180-4)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA-384",
    "source": "FIPS 180-4 / di-mgt.com.au SHA test vector aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA-384 is a truncated variant of SHA-512. 48-byte output.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515"},
    {"id": 13, "input_ascii": "Python", "output_hex": "3775eb53318c3a4717264af862e03a7807511c350b4342c062362cab558ef0169753f026bcb4ced8561b42fbccf3ea71"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "5d91ac7e74e62b5c728904b40f10784d66b7af9cb6302123e48c92f0432ceb8d2a92c02de77dcb29ed75c4b42bde46f4"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "8a8d9649ea04e993a6ca7135af7e3392cc5fca84f8531cac7aa3feed4eb98f55dcbe0f3284b61c6f35f98b02cc644b4c"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "2e404b9339da795776e510d96930b3be2904c500395b8cb7413334b82d4dec413b4b8113045a05bbbcff846f027423f6"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef760c7e27f3c464d3829f56c0d53808b0b"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "53871b26a08e90cb62142f2a39f0b80de41792322b0ca5602b6eb7b5cf067c49498a7492bb9364bbf90f40c1c5412105"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "ed845f8b4f2a6d5da86a3bec90352d916d6a66e3420d720e16439adf238f129182c8c64fc4ec8c1e6506bc2b4888baf9"},

]
