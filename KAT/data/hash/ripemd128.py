meta = {
    "group": "hash",
    "algorithm": "ripemd-128",
    "source": "RIPEMD-128 specification — Dobbertin, Bosselaers, Preneel 1996",
    "source_ref": "https://homes.esat.kuleuven.be/~bosselae/ripemd160.html",
    "generated_by": "GitHub Copilot",
    "date": "2025-07-14",
    "notes": (
        "Official test vectors from the RIPEMD-160/128 specification page at KU Leuven COSIC. "
        "RIPEMD-128 produces a 128-bit (16-byte) digest. "
        "All inputs are ASCII strings unless noted."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "cdf26213a150dc3ecb610f18f6b38b46",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "86be7afa339d0fc7cfc785e72f578d33",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "c14a12199c66e4ba84636b0f69144c77",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "9e327b3d6e523062afc1132d7df9d1b8",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "fd2aa607f71dc8f510714922b371834e",
    },
    {
        "id": 6,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "a1aa0689d0fafa2ddc22e88b49133a06",
    },
    {
        "id": 7,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "d1e959eb179c911faea4624c60c5c702",
    },
    {
        "id": 8,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "3f45ef194732c2dbb2c4a2c769795fa3",
    },
    {
        "id": 9,
        "input_repeat": {"char": "a", "count": 1_000_000},
        "output_hex": "4a7f5723f954eba1216c9d8f6320431f",
    },
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "3fa9b57f053c053fbe2735b2380db596"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "3807aaaec58fe336733fa55ed13259d9"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "67f9fe75ca2886dc76ad00f7276bdeba"},
    {"id": 13, "input_ascii": "Python", "output_hex": "0056ccc602a9fcaeaaaf6116d5ba94fe"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "418486955c126b27903aa01fef5d5d15"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "6356ebd92cd62ee084789c6ec8eb3de3"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "680716ac638f0d601982c696d37e5e56"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "8d8b1b4c4621c35d1083f6167ed60769"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "d4ecc913e1df776bf48de9d55b1f2546"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "4afc6b2313c8543fccca4d1d8e268893"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "6f1921e5d5b0579c737805bd839dc97d"},

]
