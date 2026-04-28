# KAT/data/hash/lyra2.py
# Known Answer Tests for Lyra2 memory-hard password hashing

meta = {
    "group": "hash",
    "algorithm": "Lyra2",
    "source": "Lyra2-v3 reference C implementation — PHC submission (2015)",
    "source_ref": "https://www.password-hashing.net/submissions/Lyra2-v3.tar.gz  |  https://www.lyra-2.net/",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Lyra2 is a sponge-based memory-hard password hashing scheme (PHC finalist). "
        "Vectors computed by building Main.c from the official Lyra2-v3.tar.gz PHC "
        "submission via GCC 13.3 (Ubuntu/WSL). Compile-time params: N_COLS=16, "
        "nPARALLEL=1, BLOCK_LEN_INT64=12 (768-bit bitrate), SPONGE=0 (Blake2b). "
        "Case fields: password_hex, salt_hex, t_cost, r_cost (rows), c_cost (N_COLS), "
        "output_len, output_hex. "
        "Case 1 uses the default ASCII inputs from Main.c; cases 2-4 use the "
        "testVectors() generator (sequential-byte passwords/salts)."
    ),
}

cases = [
    # Lyra2-v3 reference C, N_COLS=16, nPARALLEL=1, sponge=Blake2b
    # Built from official Lyra2-v3.tar.gz, GCC 13 via WSL Ubuntu
    {
        "id": 1,
        "description": "Default ASCII test from Main.c",
        "password_ascii": "Lyra2 PHS",
        "salt_ascii": "saltsaltsaltsalt",
        "t_cost": 1,
        "r_cost": 4,
        "c_cost": 16,
        "output_len": 64,
        "output_hex": "477eb2cf3a68991ab7a20afcd4559d6a1add141311c4ae9b57b80d16fdf9463b654a47043918befe24ee53d3f78bd9ddfe7a8439cecf6db9f9297315f75ce877",
    },
    {
        "id": 2,
        "description": "testVectors() inlen=0, sequential salt 00..0f",
        "password_hex": "",
        "salt_hex": "000102030405060708090a0b0c0d0e0f",
        "t_cost": 1,
        "r_cost": 4,
        "c_cost": 16,
        "output_len": 64,
        "output_hex": "99cd4e9bb785f49b71ee29237b02f107c48179c1122a8c3f356ffc71a8957ed4182a4353b393d0cbd4af0c834354e2efda2697129c6e39c36472fa241ba90195",
    },
    {
        "id": 3,
        "description": "testVectors() inlen=1, pwd=00, salt 10..1f",
        "password_hex": "00",
        "salt_hex": "101112131415161718191a1b1c1d1e1f",
        "t_cost": 1,
        "r_cost": 4,
        "c_cost": 16,
        "output_len": 64,
        "output_hex": "f7187460df0f455d306b5a1f937d4966461f7408c50f0f02eb39a93e9d0854ecad7c78dd9253fd0955e5cb30c27ffe36b3235f93fed0ba4bec8805a9a5bddae3",
    },
    {
        "id": 4,
        "description": "testVectors() inlen=2, pwd=00 01, salt 20..2f",
        "password_hex": "0001",
        "salt_hex": "202122232425262728292a2b2c2d2e2f",
        "t_cost": 1,
        "r_cost": 4,
        "c_cost": 16,
        "output_len": 64,
        "output_hex": "d40aa9a85d5210fe7f9d06842d8f0de0ca566e8b0e6aa6717c413fbd94ae24882918123002d77c19c967ad714815754168a3512c1320938fb3fbfdeb0d4b466f",
    },
]
