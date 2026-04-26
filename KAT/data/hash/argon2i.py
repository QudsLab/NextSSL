# KAT/data/hash/argon2i.py
# Known Answer Tests for Argon2i (data-independent memory-hard password hash)

meta = {
    "group": "hash",
    "algorithm": "Argon2i",
    "source": "argon2-cffi library (implements RFC 9106) — computed test vectors",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc9106",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Argon2i is the data-independent variant: memory access pattern is fixed, "
        "making it resistant to side-channel attacks but somewhat weaker against "
        "GPU attacks.  Case fields: password_ascii, salt_ascii, t_cost (iterations), "
        "m_cost (KiB), p (parallelism), hash_len (bytes).  Vectors computed with "
        "argon2-cffi (no associated data, no secret key — simple mode only)."
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
        "output_hex": "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
    },
    {
        "id": 2,
        "password_ascii": "password",
        "salt_ascii": "somesalt",
        "t_cost": 3,
        "m_cost": 32,
        "p": 4,
        "hash_len": 32,
        "output_hex": "a9a7510e6db4d588ba3414cd0e094d480d683f97b9ccb612a544fe8ef65ba8e0",
    },
    {"id": 3, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "cbf2bce47e6d23999626143fabc5db69164743ee000ddd3f8895a6f82cfb9a6e"},
    {"id": 4, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "1fca5e33c7734e5351da8dec4d24b6b317912733d9df7d4f8c7da50a0d6fff78"},
    {"id": 5, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "9bec782fb84dd994630417dc331dbd068e49749c48139d9daad33a23fc068c36"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "03df1d13e10203bcc663405e31ab1687939730c9152459bca28fd10c23e38f50"},
    {"id": 7, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 4, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "e89bc5b55327105dae38193a4235367f11fd487ceca25997c3c4f3dbd42d31a5"},
    {"id": 8, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "989da65458e8be1440ae555d0b3c8ac3a6584e0d2290b9dcc915a68a71e41c1e"},
    {"id": 9, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 2, "hash_len": 32, "output_hex": "bb7102d90a580d2aa1c1a83817f24ab18c7cc810ccd2c2a0d0c80c94ad299167"},
    {"id": 10, "password_ascii": "", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "0bac21175a1922adaa0bcf9bbae93a9ad97e4592a3cb85db3726a56181e48184"},
    {"id": 11, "password_ascii": "Password1", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "065f5c607045353703fedfdebb1ef577191e6b8918322495b3c1f0066a4113e6"},
    {"id": 12, "password_ascii": "letmein", "salt_ascii": "somesalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "6f8b84b1fe0e9dcaeed2d8a7ef0d4455b6fea3aa79cb4e1ed105d85b9aed8642"},
    {"id": 13, "password_ascii": "password", "salt_ascii": "saltysalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "e3d308c26c98d0414f6cf598026a4f883f3a537d91638fa463508b0679a586a4"},
    {"id": 14, "password_ascii": "test", "salt_ascii": "testsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "88b97837d266593e507916acb7c43fd81bd008af5ae94d70407f1220ca8e4644"},
    {"id": 15, "password_ascii": "hello", "salt_ascii": "worldsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "e77c37ba4bb502c122d2805537f2f4a1b20005d253a5a698c534bde688bd7eb6"},
    {"id": 16, "password_ascii": "secret", "salt_ascii": "randomslt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "268da78aeeda88a5986badcdaaf204f11e7779394cb09b8a0206f1969c5418d9"},
    {"id": 17, "password_ascii": "admin", "salt_ascii": "adminsalt", "t_cost": 2, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "be35ad9f1876efc25e6cf24fb276a18044f4008ed2667e6d0c6b12071cc39bc7"},

    {"id": 18, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 8, "p": 1, "hash_len": 32, "output_hex": "cbf2bce47e6d23999626143fabc5db69164743ee000ddd3f8895a6f82cfb9a6e"},
    {"id": 19, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 16, "p": 1, "hash_len": 32, "output_hex": "1fca5e33c7734e5351da8dec4d24b6b317912733d9df7d4f8c7da50a0d6fff78"},
    {"id": 20, "password_ascii": "password", "salt_ascii": "somesalt", "t_cost": 1, "m_cost": 64, "p": 1, "hash_len": 32, "output_hex": "9bec782fb84dd994630417dc331dbd068e49749c48139d9daad33a23fc068c36"},

]
