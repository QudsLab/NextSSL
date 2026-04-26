# KAT/data/hash/argon2id.py
# Known Answer Tests for Argon2id (hybrid memory-hard password hash)

meta = {
    "group": "hash",
    "algorithm": "Argon2id",
    "source": "argon2-cffi library (implements RFC 9106) — computed test vectors",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc9106",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Argon2id is the recommended hybrid variant: uses data-independent memory "
        "access for the first half and data-dependent for the second half. "
        "Provides a balance between resistance to side-channel attacks and GPU "
        "attacks.  Recommended by RFC 9106 for general use. "
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
        "output_hex": "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
    },
    {
        "id": 2,
        "password_ascii": "password",
        "salt_ascii": "somesalt",
        "t_cost": 3,
        "m_cost": 32,
        "p": 4,
        "hash_len": 32,
        "output_hex": "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e",
    },
    {"id": 3, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3"},
    {"id": 4, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "3fd1f4fd38592d783450391972abe3cc1c2f2b58f8d8cbfda86a857d81d25f8d"},
    {"id": 5, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "729c7a54441bc13559bdca71348c4e554599e719c08a952601ed5c83618c1bbd"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "058202c0723cd88c24408ccac1cbf828dee63bcf3843a150ea364a1e0b4e1ff8"},
    {"id": 7, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 4, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "48d405a80fe4f71403e3f23c5cdd3301c425b6616e9c88d66220297b85c0e524"},
    {"id": 8, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "16a1a498734609dd01456da406de9f3d9da93e6c86c300a12fc1465214ce4922"},
    {"id": 9, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 2, "hash_len": 32, "output_hex": "94387415dfb84ed1977465a1e8626073adf42bd4eeae1faa1dd4e23a1ff6859f"},
    {"id": 10, "password_ascii": "", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "afa6822311a2d66fe5c27f3ccda2840f8ff25cd6e77c98f3d7bc15b8c0463a03"},
    {"id": 11, "password_ascii": "Password1", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "f9ac20d1e13278a9ca38043ac464951dd730da9affb4c0442a190b496b62c9cf"},
    {"id": 12, "password_ascii": "letmein", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "feee1b5a2f480b8b1a97fbda95308a8afad31f075154985e14c13fb929f85236"},
    {"id": 13, "password_ascii": "password", "salt_ascii": "saltysalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "e6294573a20ec62e5fc5b4d5ad510b3dd851ffa76902f89a9402fa5737f41075"},
    {"id": 14, "password_ascii": "test", "salt_ascii": "testsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "2cde4c88005af982880d63b0f068f15b9137bccb36b078d10f29a2fe171b0093"},
    {"id": 15, "password_ascii": "hello", "salt_ascii": "worldsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "3ef62f7cab5a74c87cfba43b451a4cae521dc44fa9c474f3acb184a75f20060b"},
    {"id": 16, "password_ascii": "secret", "salt_ascii": "randomslt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "7154bc035c7abfe0875eb46cde10739c30ee8d348b522dbe287bbd3604c716ed"},
    {"id": 17, "password_ascii": "admin", "salt_ascii": "adminsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "eb28c1ef8c2d636590cae433ba6320654fea0e2f217115d608e2ddc435efe454"},

    {"id": 18, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3"},
    {"id": 19, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "3fd1f4fd38592d783450391972abe3cc1c2f2b58f8d8cbfda86a857d81d25f8d"},
    {"id": 20, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "729c7a54441bc13559bdca71348c4e554599e719c08a952601ed5c83618c1bbd"},

]
