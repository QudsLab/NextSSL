# KAT/data/hash/catena.py
# Known Answer Tests for Catena password hashing scheme

meta = {
    "group": "hash",
    "algorithm": "Catena",
    "source": "Catena-v5 reference C implementation — PHC submission by Christian Forler, Stefan Lucks, Jakob Wenzel (2016)",
    "source_ref": "https://www.password-hashing.net/submissions/Catena-v5.tar.gz  |  https://github.com/medsec/catena",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Catena is a memory-hard password scrambling framework (PHC finalist). "
        "Vectors computed by building catena_test_vectors.c from the official "
        "Catena-v5.tar.gz PHC submission via GCC 13.3 (Ubuntu/WSL). "
        "Variant: Catena-BRG (Dragonfly graph), LAMBDA=2, output=64 bytes (H_LEN). "
        "Case fields: variant, password_ascii, salt_ascii, ad_ascii, "
        "lambda_, garlic (g_high == g_low in simpletest), output_len, output_hex. "
        "BRG uses a Bit-Reversal Graph; DBG uses a Double-Butterfly Graph."
    ),
}

cases = [
    # Catena-BRG (Dragonfly), LAMBDA=2 — from catena_test_vectors.c simpletest()
    # Built from official Catena-v5.tar.gz, GCC 13 via WSL Ubuntu
    {
        "id": 1,
        "variant": "Catena-BRG",
        "password_ascii": "password",
        "salt_ascii": "salt",
        "ad_ascii": "",
        "lambda_": 2,
        "garlic": 1,
        "output_len": 64,
        "output_hex": "3e107076cdda8696077d8b0e610b434e8659e15c091233470f9fb41f7fade1e1475b2d0932d3c9d14cf8a14f4bafb79ff6589c33aa86ef9a7d9a447026ce40ce",
    },
    {
        "id": 2,
        "variant": "Catena-BRG",
        "password_ascii": "password",
        "salt_ascii": "salt",
        "ad_ascii": "",
        "lambda_": 2,
        "garlic": 10,
        "output_len": 64,
        "output_hex": "4419a62bf061a5d69c9ff1e5d9be6ca5808bffb814a3eeb5636fac3e46433d313ba44c1df5d290756d4102b8dc5258ea67af32d79ee2ea413b6891bb065ae845",
    },
    {
        "id": 3,
        "variant": "Catena-BRG",
        "password_ascii": "password",
        "salt_ascii": "salt",
        "ad_ascii": "data",
        "lambda_": 2,
        "garlic": 10,
        "output_len": 64,
        "output_hex": "f2f38d02e327a9d54b4b306bcce0db4a9662b2c8e64c45fb536c958df8cd1d6531f699126dd53118ca15ac8a1772c138163654b223427516fdcfaa22fd1de601",
    },
    {
        "id": 4,
        "variant": "Catena-BRG",
        "password_ascii": "passwordPASSWORDpassword",
        "salt_ascii": "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        "ad_ascii": "",
        "lambda_": 2,
        "garlic": 10,
        "output_len": 64,
        "output_hex": "c3dbe46dbed4634f5f2036fc9da34fc0617ebb74403f709a7d5d66e2fe490e0eef1740e5dce8dccd0271c8e893ca3106fd2676abfa2ebd3da0a90181f3cb4451",
    },
]
