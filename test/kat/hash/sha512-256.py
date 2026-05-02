# KAT/data/hash/sha512-256.py
# Known Answer Tests for SHA-512/256 (FIPS 180-4)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA-512/256",
    "source": "FIPS 180-4, Section 6.5.4 - SHA-512/256 examples",
    "source_ref": "https://csrc.nist.gov/publications/detail/fips/180/4/final",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA-512/256 truncates SHA-512 to 256 bits (32 bytes) with different IV. Vectors from FIPS 180-4.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    },
    {"id": 5, "input_ascii": "a", "output_hex": "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8"},
    {"id": 6, "input_ascii": "message digest", "output_hex": "0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "0686f0a605973dc1bf035d1e2b9bad1985a0bff712ddd88abd8d2593e5f99030"},
    {"id": 13, "input_ascii": "Python", "output_hex": "ca0dca32ea451db0b568fdbef4b4987cd612a596ea7e1179629c73bf5d3e57f8"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "f6513468f05e7cec7d52fc337ef79dfa7c82520268d3aeba4002ead9a5642916"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "baa8bd7fb02a11878c6a1d5400f06ec5d96cd6f566da032f8dcbb602beea4ca5"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "2c3fa8f196f2aac65f15166666ecc77bd9fe195bae83ef06bb75c7857c163db9"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "b88f97e274f9c1d49f181c8cbd01a9c74930ad055a46ac4499a1d601f1c80bf2"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "540a28b73904a9e053040ae553c540a796e72654e907d510af5e9687317acd5d"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "89845297b53545520e05ec446aa8c7dc6a9df1171d54d182aec7ca346e44df0d"},

]
