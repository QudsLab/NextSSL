# KAT/data/hash/sha3-256.py
# Known Answer Tests for SHA3-256 (FIPS 202)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA3-256",
    "source": "FIPS 202 / di-mgt.com.au SHA test vector aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA3-256 is NIST FIPS 202 standard (Keccak with SHA-3 domain separation). 32-byte output.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "cc80b0b13ba89613d93f02ee7ccbe72ee26c6edfe577f22e63a1380221caedbc"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"},
    {"id": 13, "input_ascii": "Python", "output_hex": "e03ab32cde5468b1038690f12eff5c3a6a9ecfd043551e238528b71aab79d9cb"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "78c2a04624b9328ae0e40cb8cdd29980f6ff55abf2dca68e3412d09eed4b9d03"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "f6fe8de5c8f5014786f07e9f7b08130f920dd55e587d47021686b26cf2323deb"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "043d104b5480439c7acff8831ee195183928d9b7f8fcb0c655a086a87923ffee"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "6ea6efe1dbf991d7f6d442dfe3d6036003071fa55fd438149fb845cb13f15906"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "c6fdd7a7f70862b36a26ccd14752268061e98103299b28fe7763bd9629926f4b"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "01da8843e976913aa5c15a62d45f1c9267391dcbd0a76ad411919043f374a163"},

]
