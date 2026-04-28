# KAT/data/hash/balloon.py
# Known Answer Tests for Balloon Hashing (SHA-256 variant)

meta = {
    "group": "hash",
    "algorithm": "Balloon",
    "source": "Boneh, Corrigan-Gibbs, Schechter 2016 — pure Python reference",
    "source_ref": "https://eprint.iacr.org/2016/027",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "BalloonHash using SHA-256 as the underlying primitive (BALLOON-SHA256). "
        "Parameters: s_cost (space cost, blocks), t_cost (time cost, rounds), "
        "delta (number of random dependencies per block, default 3). "
        "Case fields: password_ascii, salt_ascii, s_cost, t_cost, delta, output_hex. "
        "Vectors computed with a pure Python implementation following Section 2.1 "
        "of the Balloon paper.  Output is the final 32-byte block (SHA-256 size)."
    ),
}

cases = [
    {
        "id": 1,
        "password_ascii": "password",
        "salt_ascii": "salt",
        "s_cost": 16,
        "t_cost": 3,
        "delta": 3,
        "output_hex": "dffbc516a40c90a0dbfdf7a629cc9afceb2c9214375fe74de3e174f22dec619c",
    },
    {
        "id": 2,
        "password_ascii": "",
        "salt_ascii": "",
        "s_cost": 16,
        "t_cost": 3,
        "delta": 3,
        "output_hex": "b1da86c9651a753dcf74869e7c8537b4372bc9608ce8793d3c2bc10a6fb42822",
    },
    {
        "id": 3,
        "password_ascii": "abc",
        "salt_ascii": "salt",
        "s_cost": 32,
        "t_cost": 4,
        "delta": 3,
        "output_hex": "952045b2392631c8b278303f3cbbc6411644e4661005b73bbf66e28778a6fe10",
    },
    {
        "id": 4,
        "password_ascii": "password",
        "salt_ascii": "somesalt",
        "s_cost": 64,
        "t_cost": 1,
        "delta": 3,
        "output_hex": "ea02bcbf0c5f06a0b05ee7716d86201330df309adeac1662a350a90914e4f9d7",
    },
    {"id": 5, "password_ascii": "password", "salt_ascii": "somesalt", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "02bbf4d86e11f9c737e2feed4e6e225fbde58d661526f445c9318c528b20d2fb"},
    {"id": 6, "password_ascii": "password", "salt_ascii": "somesalt", "s_cost": 8, "t_cost": 2, "delta": 3, "output_hex": "e263bdc808588425b68400d5848bcb262d07f8fef5822c549d0528f9e936ae24"},
    {"id": 7, "password_ascii": "password", "salt_ascii": "somesalt", "s_cost": 8, "t_cost": 3, "delta": 3, "output_hex": "500a66b735b732111097ae53add208dc2b38d24e275fb2bfbdfeec034088ef6e"},
    {"id": 8, "password_ascii": "abc", "salt_ascii": "salt", "s_cost": 16, "t_cost": 1, "delta": 3, "output_hex": "a54ae8ced35c9ef8cefbd14baf94c25b5a7e92e599c7abba877a431bc753cb5a"},
    {"id": 9, "password_ascii": "abc", "salt_ascii": "salt", "s_cost": 16, "t_cost": 2, "delta": 3, "output_hex": "7e808971c488246f75dde0527aedcd3de9a3df05b09584b91015e2bdc3b79129"},
    {"id": 10, "password_ascii": "", "salt_ascii": "salt", "s_cost": 16, "t_cost": 1, "delta": 3, "output_hex": "8625f668d2335b65d610a46975770ccfb05f53d7c3e5589a0dff7d3aad8700c3"},
    {"id": 11, "password_ascii": "password", "salt_ascii": "", "s_cost": 16, "t_cost": 1, "delta": 3, "output_hex": "71ddb65f9c00ec709f4a3801aea8d6b93bf08cff35522682acbe45fd6b0f5f49"},
    {"id": 12, "password_ascii": "hello", "salt_ascii": "world", "s_cost": 16, "t_cost": 1, "delta": 3, "output_hex": "7d674871de9dac85a80f67891d0b24bb4d4b4825e57e31e1cf695f8a06dbf58f"},
    {"id": 13, "password_ascii": "test", "salt_ascii": "test", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "77bee21998ed47150b96e51449852aa8ad80eb86c159a3ccf4e41c9212aedda9"},
    {"id": 14, "password_ascii": "Password1", "salt_ascii": "somesalt", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "865da91400d2daec163bf5c2e98e292598ddc94fc1eb1ff91c211bd56c9dc8fd"},
    {"id": 15, "password_ascii": "letmein", "salt_ascii": "NaCl", "s_cost": 8, "t_cost": 2, "delta": 3, "output_hex": "74d30c11f7b1330786db97564579139d7c085b6b2346129ed1d72ff58b835617"},
    {"id": 16, "password_ascii": "", "salt_ascii": "", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "85c4fab835cb25e72308cce614faa500b913efa3b41e4b56878acf4e27dc0299"},
    {"id": 17, "password_ascii": "hunter2", "salt_ascii": "pepper", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "e8f82ef0f31e0c6e0f65bf3b263816752738e409922b042fff4b55a2693ce1f6"},
    {"id": 18, "password_ascii": "secret", "salt_ascii": "random", "s_cost": 16, "t_cost": 3, "delta": 3, "output_hex": "7f0842e1294891576f4bc1e92d841d3aaa3d8c2b9cc21c8e560a5ed5fa302207"},
    {"id": 19, "password_ascii": "admin", "salt_ascii": "salt1234", "s_cost": 8, "t_cost": 1, "delta": 3, "output_hex": "33ec30bc0c0aa0678526ebcad6b30fe2aec4c2a976b6b687b4a4c84a8560b392"},
    {"id": 20, "password_ascii": "password", "salt_ascii": "somesalt", "s_cost": 16, "t_cost": 3, "delta": 4, "output_hex": "74e55da6a4c3385f66f9fde772cb296c5ff0a59d3837afb29556bc2df8e20723"},

]
