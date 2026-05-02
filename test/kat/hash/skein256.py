# KAT/data/hash/skein256.py
# Known Answer Tests for Skein-256 (256-bit output, 256-bit internal state)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "Skein-256",
    "source": "Skein v1.3 specification — Ferguson, Lucks, Schneier, Whiting, Bellare, Kohno, Callas, Walker",
    "source_ref": "https://www.schneier.com/academic/skein/",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Skein-256 uses a 256-bit Threefish internal state.  This is the simple "
        "hash mode (no tree, no MAC, no personalisation) with 256-bit output. "
        "Vectors computed with the pyskein library (Skein v1.3)."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "7fba44ff1a31d71a0c1f82e6e82fb5e9ac6c92a39c9185b9951fed82d82fe635",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "258bdec343b9fde1639221a5ae0144a96e552e5288753c5fec76c05fc2fc1870",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "4d2ce0062b5eb3a4db95bc1117dd8aa014f6cd50fdc8e64f31f7d41f9231e488",
    },
    {
        "id": 5,
        "input_ascii": "The quick brown fox jumps over the lazy dog",
        "output_hex": "c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe",
    },
    {"id": 6, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "46d8440685461b00e3ddb891b2ecc6855287d2bd8834a95fb1c1708b00ea5e82"},
    {"id": 7, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "7c5eb606389556b33d34eb2536459528dc0af97adbcd0ce273aeb650f598d4b2"},
    {"id": 8, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "4def7a7e5464a140ae9c3a80279fbebce4bd00f9faad819ab7e001512f67a10d"},
    {"id": 9, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "fb2f2f2deed0e1dd7ee2b91cee34e2d1c22072e1f5eaee288c35a0723eb653cd"},
    {"id": 10, "input_ascii": "Hello, World!", "output_hex": "59f315126001f93f24991de4ed5021cac2d6249862745c27c22b5ed968b29dcf"},
    {"id": 11, "input_ascii": "Python", "output_hex": "d01448ab44bb8d692e68b75cb49120d24e8802bc11d730839be83d5e4524f53d"},
    {"id": 12, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "5cbbc14a7396c923224015557547243ab86a258112f279b1ab975d5062464566"},
    {"id": 13, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "0afc78e7105db49dd0f30b25a55965ddad71b997b2ceff996dce33fa6d433e19"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "0a0a70d9454c73065a616071ae3eca5661b09ba67f9968be7a3d527c4ff50aff"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "3bdcd6f280ff42c25eea33720379cfcb10cc8e1b3d0c4f614eaac97164d56094"},
    {"id": 16, "input_ascii": A_LONG, "output_hex": "570c70901e31994c1f7b960f3fbdcf8db003e533396d48389f46d37c3ed14738"},
    {"id": 17, "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output_hex": "21cdd023e2b2e90a1f137d050c5a81bc84545048e1ed035d87e9e721f19ffea2"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "f5c65594cb4c68afc445a4cf4107dbe2f92eff0b9990afbbdb9d2b3acdedba0f"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "8af8ab5607985f8e44fddb72eea283b74b42716e0f2f5fb2d9cc26bcd997e39c"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "9dfca0f5758091946f3c9c80203890057aa345f063318df929d0eb32b9e4614f"},

]
