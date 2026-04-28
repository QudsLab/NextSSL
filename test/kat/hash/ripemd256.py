meta = {
    "group": "hash",
    "algorithm": "ripemd-256",
    "source": "RIPEMD-256 specification — Dobbertin, Bosselaers, Preneel 1996 (optional extension)",
    "source_ref": "https://homes.esat.kuleuven.be/~bosselae/ripemd160.html",
    "generated_by": "GitHub Copilot",
    "date": "2025-07-14",
    "notes": (
        "Official test vectors from the RIPEMD-160 specification page at KU Leuven COSIC. "
        "RIPEMD-256 is an optional extension of RIPEMD-128 that produces a 256-bit (32-byte) digest "
        "without increasing the security level beyond RIPEMD-128. "
        "All inputs are ASCII strings unless noted."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
    },
    {
        "id": 6,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
    },
    {
        "id": 7,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
    },
    {
        "id": 8,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
    },
    {
        "id": 9,
        "input_repeat": {"char": "a", "count": 1_000_000},
        "output_hex": "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
    },
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "c3b0c2f764ac6d576a6c430fb61a6f2255b4fa833e094b1ba8c1e29b6353036f"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "b44055d843dea5bcd2151e52b1a0dbc5e8e34493e5fe2f000c0e71f73c3ddcae"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "567750c6d34dcba7ae038a80016f3ca3260ec25bfdb0b68bbb8e730b00b2447d"},
    {"id": 13, "input_ascii": "Python", "output_hex": "4d05b7ec4cc1b99e9f25015805daf6848457798aa5b579b719ddf7bc73e08ec3"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "7780dbe5f483206a1e397f7850f23ee6c595ff2d1a1846eb3ec6b0be03f1e161"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "d210e3e343f73334320d4b8f28fc8079ca06f30f0ba6f7baa8928a707ac45593"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "8147678472c129cabb59f57f637c622ccd5707af80a583303e6dde7d0800ced6"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "33b9c6f5f888e077f81067c9c082bf0da7ef9738e20d69b0864418ce568cd32c"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "9f111a4e8978e8bc37a87f320c5e8e92eb011dfc947caf69519909ffe093fbb7"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "629be273f8e835df6ae67a1f4f8582aad033ba8fb8faebca731eb1eeaaca8850"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "9836cad714a598b572302bb09bd430e94e1f0c294f1b0a94efc32606a964fcf1"},

]
