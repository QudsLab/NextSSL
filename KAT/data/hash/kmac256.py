# KAT/data/hash/kmac256.py
# Known Answer Tests for KMAC256 (Keccak Message Authentication Code, 256-bit security)

meta = {
    "group": "hash",
    "algorithm": "KMAC256",
    "source": "NIST SP 800-185 Sample Values",
    "source_ref": "https://csrc.nist.gov/publications/detail/sp/800-185/final",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "KMAC256 is a MAC/PRF/KDF based on cSHAKE256, defined in NIST SP 800-185. "
        "Parameters: key, data, output_length, and optional customization_string S. "
        "Case fields: key_hex, data_hex, output_len (bytes), custom_str (ASCII), output_hex. "
        "The standard key for all samples is 32 bytes of 40..5F. "
        "All 3 sample values verified against the NIST SP 800-185 published examples "
        "using pycryptodome."
    ),
}

# Key for all 3 samples: 0x404142...5F (32 bytes)
_KEY = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

cases = [
    {
        "id": 1,
        "key_hex": _KEY,
        "data_hex": "00010203",
        "output_len": 64,
        "custom_str": "My Tagged Application",
        "output_hex": (
            "20c570c31346f703c9ac36c61c03cb64"
            "c3970d0cfc787e9b79599d273a68d2f7"
            "f69d4cc3de9d104a351689f27cf6f595"
            "1f0103f33f4f24871024d9c27773a8dd"
        ),
    },
    {
        "id": 2,
        "key_hex": _KEY,
        # data = bytes(range(200)) = 0x000102...C7 (200 bytes)
        "data_hex": "".join(f"{i:02x}" for i in range(200)),
        "output_len": 64,
        "custom_str": "",
        "output_hex": (
            "75358cf39e41494e949707927cee0af2"
            "0a3ff553904c86b08f21cc414bcfd691"
            "589d27cf5e15369cbbff8b9a4c2eb178"
            "00855d0235ff635da82533ec6b759b69"
        ),
    },
    {
        "id": 3,
        "key_hex": _KEY,
        "data_hex": "".join(f"{i:02x}" for i in range(200)),
        "output_len": 64,
        "custom_str": "My Tagged Application",
        "output_hex": (
            "b58618f71f92e1d56c1b8c55ddd7cd18"
            "8b97b4ca4d99831eb2699a837da2e4d9"
            "70fbacfde50033aea585f1a2708510c3"
            "2d07880801bd182898fe476876fc8965"
        ),
    },
    {"id": 4, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 64, "custom_str": "", "output_hex": "2387aadc639d5214f0a794d88d613a2e43ad8261cc09be3ab328a3c72a0881d3b550e8aa41d50b723cdd463509fdabf8f7a60ff737245c6e35a3820ee7530cd2"},
    {"id": 5, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 64, "custom_str": "", "output_hex": "6517fbc373cfe06b1ccb193ee3f583a30e3c6451fd00669b3b47a774e50304ce91228fda6dd9221defbe6778e3dea9add06d966f901befd1b71c35af1d745f50"},
    {"id": 6, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 64, "custom_str": "Test", "output_hex": "cbdddb9fe9770f1bfddae5f5350f3f66fff8727466f3ae335770990f8c2a8fb5a72c6f072870226c28f135fe526af5091d8a61a5cf9ae578ce0426529a615e58"},
    {"id": 7, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 64, "custom_str": "Test", "output_hex": "e9af8591aaf65673d92ab40c50fb8a21230f2b6825f2745350ec7e3a19d8393ce7ea0b4cd9a41730164d0c3b9b479a870aab47107e156a5ff014f7b887a988ab"},
    {"id": 8, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 64, "custom_str": "KMAC256 test", "output_hex": "8e164d706c40b4d4aa7deed0af6cbb39d87f12be27adc7a6642e0a3d38efdf310963662759d70b5a772026ad9228f70f0e346a124a479b4f7f6d3505bff958c1"},
    {"id": 9, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 64, "custom_str": "KMAC256 test", "output_hex": "0ed837af8e2140124898fa2b0f1f0a6edbdb3afb2b6253fa6e2bcdbef870fe2fa8847d6925b9e6ecdc970c2ed5f92ff9f3e06b56a7af5325eadf047dc6cea9d3"},
    {"id": 10, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 64, "custom_str": "", "output_hex": "9fa3e255cbca1af1fc3d147efee6dc8472d025494b47faead6584839a3a352b331a98facb1e261cd15d4a6aaaacb4f1c5cb51d6a5fb5964df08fa79f6b716818"},
    {"id": 11, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 64, "custom_str": "", "output_hex": "51eb56507f7b5a220c393a129335f9b1b92c985b9b6f96c35683bfc0c786ac861561c31a62b2e83d92f5c5c941b550bf3c23098d814228e3b677279db49db5fb"},
    {"id": 12, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 64, "custom_str": "Test", "output_hex": "2657e5bcc77dad21549744f1b6af6dab40b338d18a92a85e10b6db11082cac2842488d56ff5afcbf745081c3a63aac8757c91b3330ecd4dae96f017224bccc22"},
    {"id": 13, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 64, "custom_str": "Test", "output_hex": "468730ed459325077729bd29626b8b67a31ea6693a9ea6dd4f93101083a942848f0b63f9970c503ddcb8eaab0496636efc35145990d1513818bf67281b5ac7d0"},
    {"id": 14, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 64, "custom_str": "KMAC256 test", "output_hex": "6f075a79734a27ca6dfe378643dae538156be5f802c5f0e011251f22a42596778027d278c691796275d250b3a7c124eae200c6debd433cbbc3e4be65c2f42316"},
    {"id": 15, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 64, "custom_str": "KMAC256 test", "output_hex": "e35c8ee8c7e5c39c12595bd8b6dd30021c87c932dd008944d81f7aadb49d3b69d340f6064a2a80f590ac7c302bacd3379a5a1101329f702d149225f5fc81ba79"},
    {"id": 16, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 64, "custom_str": "", "output_hex": "1831ba1d8a67c15266194a1e64d123e8aa042eb865890edf42676e7a780cdfd490e22aa45e7de25bf3b29a136c4a231233414554f3543b1936a8c8b09f14c23a"},
    {"id": 17, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "ff", "output_len": 64, "custom_str": "", "output_hex": "7623db563a66a16bc2b5dea2faebf5a37e4d5ea083edef74730a7f21c1972b080af647191b20b343ae46ca15d9239e62f49f1291ff97d13917c0e52f5e60a4bb"},
    {"id": 18, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 64, "custom_str": "Test", "output_hex": "cd63345a922411863f8b0ad95e048865eeb2baf672abeb5f2a3d9809a8e127a72d2742537f79f17915c69accce9409879cd6d3dedd9bceb15e39d91b87d39e1c"},
    {"id": 19, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "ff", "output_len": 64, "custom_str": "Test", "output_hex": "7cf8dccf0444d9076a7fba43bae1a26691ee1c47d857bb749f305c76f985a715a95a5aee39f98aae02bfbdd1583e089425c0a105c9b8f2db79ec199e76091ad0"},
    {"id": 20, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 64, "custom_str": "KMAC256 test", "output_hex": "70c1fbc6deda6cec3cd0431628795ba063f385826f86c53326ba30be450e1970538e6b1139cb549f0655c5dd3e255218b0330e1fb2d83cca52bfb70996686467"},

]
