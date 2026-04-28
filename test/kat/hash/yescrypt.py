# KAT/data/hash/yescrypt.py
# Known Answer Tests for yescrypt password hashing

meta = {
    "group": "hash",
    "algorithm": "yescrypt",
    "source": "pyescrypt 0.1.0 — Python bindings for yescrypt reference C implementation",
    "source_ref": "https://github.com/0xcb/pyescrypt  |  https://www.openwall.com/yescrypt/",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "yescrypt is a scalable password hashing scheme, successor to scrypt. "
        "Vectors computed via pyescrypt 0.1.0 (CFFI bindings to yescrypt reference C). "
        "Parameters: N (CPU/memory cost), r (block size), p (parallelism), "
        "t (time cost), output_len (bytes). Mode=RAW (YESCRYPT_DEFAULTS flags). "
        "N=16 (2^4) is used here for speed; production deployments use N>=2^15."
    ),
}

cases = [
    # pyescrypt N=16, r=1, p=1, t=0, mode=RAW
    {
        "id": 1,
        "password_ascii": "",
        "salt_ascii": "",
        "N": 16,
        "r": 1,
        "p": 1,
        "t": 0,
        "output_len": 64,
        "output_hex": "46c3f4d377162c6528d6a53e4f05fc1196663aaa71f6b9007449b379f53aae79b409de0072223da277aed8c828bb1ea959822389d2edacd15a8ecfe79e8b6ca1",
    },
    {
        "id": 2,
        "password_ascii": "",
        "salt_ascii": "",
        "N": 16,
        "r": 1,
        "p": 1,
        "t": 0,
        "output_len": 8,
        "output_hex": "46c3f4d377162c65",
    },
    {
        "id": 3,
        "password_ascii": "password",
        "salt_ascii": "NaCl",
        "N": 16,
        "r": 1,
        "p": 1,
        "t": 0,
        "output_len": 64,
        "output_hex": "f568919a3d7cbdfdeeeaa62f7b2e58262463bd5312587e96ee488443bde1659b9a767a2791d5010bac18e030b140d307ebbfb5a576f4470f6bfec498e4d16efb",
    },
    {
        "id": 4,
        "password_ascii": "pleaseletmein",
        "salt_ascii": "SodiumChloride",
        "N": 16,
        "r": 1,
        "p": 1,
        "t": 0,
        "output_len": 64,
        "output_hex": "2eea88be1a85853b9ce5670de06dcb14cf9097119d69fe06e9fd24c6b3d345a162daa7bcb943918f847e7eb865bfae31e05839b37a0958e93322d00858fae66c",
    },
    {"id": 5, "password_ascii": "password", "salt_ascii": "salt", "N": 4, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "6f9974a4554b711f9a5bd07c995b5398478ed6040264b8e463950473f2a2c48c"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "salt", "N": 8, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "028f3e49bc512fff866d1f85ec757597247acacdc09a432b397ce374f41d7079"},

    {"id": 7, "password_ascii": "password", "salt_ascii": "salt", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "43a373cf7904bdf1c5f85a5e6cc61ad9d0189ef35e8e1a68031e66069a012eb2"},
    {"id": 8, "password_ascii": "password", "salt_ascii": "salt", "N": 2048, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "bf5515cf4af1d839dc7192bdc230587926f284093c3fc0d28e4839dddc3988aa"},
    {"id": 9, "password_ascii": "password", "salt_ascii": "salt", "N": 4096, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "a63856859c642f387182b7e4e8e2ba4932b747db9edb9098e6075488573d2271"},
    {"id": 10, "password_ascii": "abc", "salt_ascii": "NaCl", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "8b54b14e5ab8470e1a014f7652689312b8a60f8be89ee1725b6a20a5df5f34fd"},
    {"id": 11, "password_ascii": "", "salt_ascii": "salt", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "6d4a898960d7f30956c6a1fe6055ba9240c446fc1e7c5ee43c37cc8e3cd762d8"},
    {"id": 12, "password_ascii": "password", "salt_ascii": "", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "18995c64e27aeef89c941504e2352acd8275e67181ac14822e8a55ce5ce01634"},
    {"id": 13, "password_ascii": "hello", "salt_ascii": "world", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "bf19c0384534d3f293e9ef032a7247b78d9d7802e5469cd424308aa2a028b20c"},
    {"id": 14, "password_ascii": "test", "salt_ascii": "test", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "46f643f1e507d08c6de560c2c5d5ab6f676a3f7492c1b52f244c57738ae9e7ce"},
    {"id": 15, "password_ascii": "Password1", "salt_ascii": "somesalt", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "c27561cc5382071c2fbdda3227218c2215c6f8ed54aeda30bfc141053f902e27"},
    {"id": 16, "password_ascii": "password", "salt_ascii": "salt", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 64, "output_hex": "43a373cf7904bdf1c5f85a5e6cc61ad9d0189ef35e8e1a68031e66069a012eb2"},
    {"id": 17, "password_ascii": "password", "salt_ascii": "salt", "N": 1024, "r": 8, "p": 2, "t": 0, "output_len": 32, "output_hex": "f2b8e518697f4137db78b26190efdc83fbc6cfc19809ce0c593f9885a9e8b278"},
    {"id": 18, "password_ascii": "password", "salt_ascii": "salt", "N": 1024, "r": 16, "p": 1, "t": 0, "output_len": 32, "output_hex": "6f163a3baf66c19a6da2ddc976cf633e4d05b7d12982db29a017addc3cf07399"},
    {"id": 19, "password_ascii": "password", "salt_ascii": "salt", "N": 1024, "r": 4, "p": 1, "t": 0, "output_len": 32, "output_hex": "960e1b67a815ac3b0c024ce200ec5031586352dcad2ba46865a93c8e9fdda24f"},
    {"id": 20, "password_ascii": "admin", "salt_ascii": "adminsalt", "N": 1024, "r": 8, "p": 1, "t": 0, "output_len": 32, "output_hex": "b4a1e7d7182b7bfcd12978873d51a669768836a4a11661977677e0283c7dab05"},

]
