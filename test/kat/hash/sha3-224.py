# KAT/data/hash/sha3-224.py
# Known Answer Tests for SHA3-224 (FIPS 202)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA3-224",
    "source": "FIPS 202 / di-mgt.com.au SHA test vector aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA3-224 is NIST FIPS 202 standard (Keccak with SHA-3 domain separation). 28-byte output.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "b770eb6ac3ac52bd2f9e8dc186d6b604e7c3b7ffc8bd9220b0078ced"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "853048fb8b11462b6100385633c0cc8dcdc6e2b8e376c28102bc84f2"},
    {"id": 13, "input_ascii": "Python", "output_hex": "fc702ae5a7c56e60a880a5bcfe45d1e763682ddb39d531c38820bb00"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "882e612fac7ae6fa2db1267312fb0a5fd479c6c556b0a101beaf4f21"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "08d654d94751580d7730b56064734b662eff7b2d159bed9ad55c935c"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "ce06309528da04278a8072ca96610a47298cbca3a9b6a0ee7f581316"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "5aa2b510fa3c12425af590590bf252d61f8be3bb30fdf521fda7562e"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "ad5c4adcaa5ae42d9ba3ef45f530b7165e1705dd4eb78ef8ab2f8bba"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "9877af03f5e1919851d0ef4ce6b23f1e85a40b446d93713f4c6e6dcd"},

]
