# Bech32 / Bech32m — BIP 173 / BIP 350 human-readable address encoding
meta = {
    "group": "encoding",
    "algorithm": "bech32",
    "source": "bip",
    "source_ref": "BIP-173 / BIP-350 / KAT/repo/encoding/bech32/ref/python/tests.py",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # --- Valid Bech32 (BIP-173 checksum constant 1) ---
    {"id": "bech32-valid-0001",  "variant": "bech32",  "encoded": "A12UEL5L",    "valid": True},
    {"id": "bech32-valid-0002",  "variant": "bech32",  "encoded": "a12uel5l",    "valid": True},
    {"id": "bech32-valid-0003",  "variant": "bech32",
     "encoded": "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "valid": True},
    {"id": "bech32-valid-0004",  "variant": "bech32",
     "encoded": "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
     "valid": True},
    {"id": "bech32-valid-0005",  "variant": "bech32",
     "encoded": "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "valid": True},
    # --- Valid Bech32m (BIP-350 checksum constant 0x2bc830a3) ---
    {"id": "bech32m-valid-0001", "variant": "bech32m", "encoded": "A1LQFN3A",    "valid": True},
    {"id": "bech32m-valid-0002", "variant": "bech32m", "encoded": "a1lqfn3a",    "valid": True},
    {"id": "bech32m-valid-0003", "variant": "bech32m",
     "encoded": "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "valid": True},
    {"id": "bech32m-valid-0004", "variant": "bech32m",
     "encoded": "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "valid": True},
    # --- Invalid Bech32 (must fail) ---
    {"id": "bech32-invalid-0001", "variant": "bech32", "encoded": "pzry9x0s0muk",  "valid": False, "note": "No separator"},
    {"id": "bech32-invalid-0002", "variant": "bech32", "encoded": "1pzry9x0s0muk", "valid": False, "note": "Empty HRP"},
    {"id": "bech32-invalid-0003", "variant": "bech32", "encoded": "x1b4n0q5v",     "valid": False, "note": "Invalid data character"},
    {"id": "bech32-invalid-0004", "variant": "bech32", "encoded": "A1G7SGD8",      "valid": False, "note": "Checksum with uppercase HRP"},
    # --- Valid SegWit addresses (decoded scriptPubKey) ---
    {"id": "bech32-segwit-0001",
     "variant": "segwit",
     "hrp": "bc",
     "encoded": "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
     "scriptpubkey_hex": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
     "wit_version": 0},
    {"id": "bech32-segwit-0002",
     "variant": "segwit",
     "hrp": "bc",
     "encoded": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
     "scriptpubkey_hex": "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "wit_version": 1},
    {"id": 16, "variant": "bech32", "encoded": "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", "valid": True},
    {"id": 17, "variant": "bech32", "encoded": "7hnsctp8r50k10c0", "valid": True},
    {"id": 18, "variant": "bech32", "encoded": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "valid": True},
    {"id": 19, "variant": "bech32m", "encoded": "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47hugq", "valid": True},
    {"id": 20, "variant": "bech32m", "encoded": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "valid": True},

]
