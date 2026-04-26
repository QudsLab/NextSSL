meta = {
    "group": "hash",
    "algorithm": "ripemd-160",
    "source": "RIPEMD-160 specification — Dobbertin, Bosselaers, Preneel 1996",
    "source_ref": "https://homes.esat.kuleuven.be/~bosselae/ripemd160.html",
    "generated_by": "GitHub Copilot",
    "date": "2025-07-14",
    "notes": (
        "Official test vectors from the RIPEMD-160 specification page at KU Leuven COSIC. "
        "RIPEMD-160 produces a 160-bit (20-byte) digest. "
        "Also referenced in ISO/IEC 10118-3:2004. "
        "All inputs are ASCII strings unless noted."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "5d0689ef49d2fae572b881b123a85ffa21595f36",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    },
    {
        "id": 6,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    },
    {
        "id": 7,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "b0e20b6e3116640286ed3a87a5713079b21f5189",
    },
    {
        "id": 8,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    },
    {
        "id": 9,
        "input_repeat": {"char": "a", "count": 1_000_000},
        "output_hex": "52783243c1697bdbe16d37f97f68f08325dc1528",
    },
    {
        "id": 10,
        "input_ascii": "The quick brown fox jumps over the lazy dog",
        "output_hex": "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
    },
    {
        "id": 11,
        "input_ascii": "The quick brown fox jumps over the lazy cog",
        "output_hex": "132072df690933835eb8b6ad0b77e7b6f14acad7",
    },
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "527a6a4b9a6da75607546842e0e00105350b1aaf"},
    {"id": 13, "input_ascii": "Python", "output_hex": "bfec2cc0044245919995ec0ea5306661e728df17"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "e72334b46c83cc70bef979e15453706c95b888be"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "9dfb7d374ad924f3f88de96291c33e9abed53e32"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "8dfdfb32b2ed5cb41a73478b4fd60cc5b4648b15"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "fd2bead7cf387c7896e2f42926fca4b4a0483d88"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "9d752daa3fb4df29837088e1e5a1acf74932e074"},

]
