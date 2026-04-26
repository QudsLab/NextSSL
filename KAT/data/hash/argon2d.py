# KAT/data/hash/argon2d.py
# Known Answer Tests for Argon2d (data-dependent memory-hard password hash)

meta = {
    "group": "hash",
    "algorithm": "Argon2d",
    "source": "argon2-cffi library (implements RFC 9106) — computed test vectors",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc9106",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Argon2d is the data-dependent variant: memory accesses depend on the password, "
        "making it faster on GPUs but susceptible to side-channel attacks. "
        "Case fields: password_ascii, salt_ascii, t_cost (iterations), m_cost (KiB), "
        "p (parallelism), hash_len (bytes).  Vectors computed with argon2-cffi "
        "(no associated data, no secret key — simple mode only)."
    ),
}

cases = [
    {
        "id": 1,
        "password_ascii": "password",
        "salt_ascii": "somesalt",
        "t_cost": 2,
        "m_cost": 65536,
        "p": 1,
        "hash_len": 32,
        "output_hex": "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf",
    },
    {
        "id": 2,
        "password_ascii": "password",
        "salt_ascii": "somesalt",
        "t_cost": 3,
        "m_cost": 32,
        "p": 4,
        "hash_len": 32,
        "output_hex": "9e34c31a47866ce0c30a90c69dd21022d5329a3b75f9c513722dd2541fe93a1a",
    },
    {"id": 3, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "c519e603ac603ec1aeb5b71ec44a6179e3f3975b14c0c97e3914c79e6363e178"},
    {"id": 4, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "321a42ea4f4df827355f94bbd4f4fda59e3ef6b07e3aa920a4a1ebda2546b168"},
    {"id": 5, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "063f9e47e2f270b195d3e16245f2f73a0c47244f1703fbc04348a0585bde7c4f"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "e742c05880c44c4df5fe79937be77897a6e41ca758affc42301f1e4040e35bd2"},
    {"id": 7, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 4, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "a54429f04c551b4c29512a04ec81c3200e8b3a0b8c6af5b41ce41292746ad81d"},
    {"id": 8, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "f920d95538648465abeeba6ae06ea532ed26df314aff60150237d8fe116f62cd"},
    {"id": 9, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 2, "hash_len": 32, "output_hex": "d6af1b803d316222b7b0c0adfee22bcabee33f4834e1fb3d40e2137ac0bb33cf"},
    {"id": 10, "password_ascii": "", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "20e18e8d89c21a58aff45cb2e3a57ec295e17f37e2c422730ffd1c6187da309e"},
    {"id": 11, "password_ascii": "Password1", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "6a1db284a564f63156476d45167e6353d0ab56bf60431e986fff809fdfc2f302"},
    {"id": 12, "password_ascii": "letmein", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "92a4c6551f91107034916b3c860a0729d3f021b18b3e1787eca66b9d0ea5f52a"},
    {"id": 13, "password_ascii": "password", "salt_ascii": "saltysalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "94aafa31bf3d6eafe745cf24795843378b6d62e181535a18d52105563e566e4c"},
    {"id": 14, "password_ascii": "test", "salt_ascii": "testsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "79e0855cf20bb338c1629501920337d3ceb67c30951748ec4d8fc0ec858b13b2"},
    {"id": 15, "password_ascii": "hello", "salt_ascii": "worldsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "aed0b886adb4fb74e00a888f99f17a1057b0c779a29733edd959811fb41300e7"},
    {"id": 16, "password_ascii": "secret", "salt_ascii": "randomslt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "8237c2b9900cf885e807885d036f145723b9f632ca576776dacb6ecb331907b7"},
    {"id": 17, "password_ascii": "admin", "salt_ascii": "adminsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "02b08c2b22de331f747f622329037c0a6835ebb625d6b1fc1624284f859d1923"},

    {"id": 18, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "c519e603ac603ec1aeb5b71ec44a6179e3f3975b14c0c97e3914c79e6363e178"},
    {"id": 19, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "321a42ea4f4df827355f94bbd4f4fda59e3ef6b07e3aa920a4a1ebda2546b168"},
    {"id": 20, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "063f9e47e2f270b195d3e16245f2f73a0c47244f1703fbc04348a0585bde7c4f"},

]
