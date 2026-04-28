meta = {
    "group": "hash",
    "algorithm": "ripemd-320",
    "source": "RIPEMD-320 specification — Dobbertin, Bosselaers, Preneel 1996 (optional extension)",
    "source_ref": "https://homes.esat.kuleuven.be/~bosselae/ripemd160.html",
    "generated_by": "GitHub Copilot",
    "date": "2025-07-14",
    "notes": (
        "Official test vectors from the RIPEMD-160 specification page at KU Leuven COSIC. "
        "RIPEMD-320 is an optional extension of RIPEMD-160 that produces a 320-bit (40-byte) digest "
        "without increasing the security level beyond RIPEMD-160. "
        "All inputs are ASCII strings unless noted."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
    },
    {
        "id": 6,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
    },
    {
        "id": 7,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
    },
    {
        "id": 8,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
    },
    {
        "id": 9,
        "input_repeat": {"char": "a", "count": 1_000_000},
        "output_hex": "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
    },
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "e7660e67549435c62141e51c9ab1dcc3b1ee9f65c0b3e561ae8f58c5dba3d21997781cd1cc6fbc34"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "393e0df728c4ce3d79e7dcfd357d5c26f5c6d64c6d652dc53b6547b214ea9183e4f61c477ebf5cb0"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "f9832e5bb00576fc56c2221f404eb77addeafe49843c773f0df3fc5a996d5934f3c96e94aeb80e89"},
    {"id": 13, "input_ascii": "Python", "output_hex": "4e4d91b7ed6d62a215ec1aff71892bf440042c5ac454f034e2ea98b478506190f4a69d9a15a0716e"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "34da276ee34f04ccf15c53170e6e71e2c3fc7ae33ad17033f2185c0cee6832abb4d741154438c54e"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "c49b2d7215293232bc94bde21658cb68e60ae66d826f1b0b8ed95ac27d56606aa7d3aedf8a014344"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "6e815badcf69d2978caf8b8bbaba941239f9847d1ff140062484cb57a0745bccf21c427705fdd30d"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "e5be83279dbb778f9efa9cdcd78062ad7b03db1fff8ddd92b1c60b9852e61be097be037bf866cbc7"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "1262ca0af08f9f7178f3252fa81d43dc1525d10d82bca7c52695ad2c8a3623711e4113b19df115b3"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "8d132dec5ff47de7a278202b49e50299aa8e1ab39f570731b0e323b9b5fc935c16d7e61c66bcbb14"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "ad1bcc613104dff743f5b587df9184829af49d259c7783a96a5843f98c6205510bb98754789539f3"},

]
