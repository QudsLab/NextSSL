# KAT/data/hash/kmac128.py
# Known Answer Tests for KMAC128 (Keccak Message Authentication Code, 128-bit security)

meta = {
    "group": "hash",
    "algorithm": "KMAC128",
    "source": "NIST SP 800-185 Sample Values",
    "source_ref": "https://csrc.nist.gov/publications/detail/sp/800-185/final",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "KMAC128 is a MAC/PRF/KDF based on cSHAKE128, defined in NIST SP 800-185. "
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
        "output_len": 32,
        "custom_str": "",
        "output_hex": "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
    },
    {
        "id": 2,
        "key_hex": _KEY,
        "data_hex": "00010203",
        "output_len": 32,
        "custom_str": "My Tagged Application",
        "output_hex": "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
    },
    {
        "id": 3,
        "key_hex": _KEY,
        # data = bytes(range(200)) = 0x000102...C7 (200 bytes)
        "data_hex": "".join(f"{i:02x}" for i in range(200)),
        "output_len": 32,
        "custom_str": "My Tagged Application",
        "output_hex": "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
    },
    {"id": 4, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 32, "custom_str": "", "output_hex": "58e8a99428d57617aa5caeae1de3db108af411286e64a00a6e1f308c3fe9557c"},
    {"id": 5, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 32, "custom_str": "", "output_hex": "02a504a0255bc4aea97387c9387085222e83dfaf46b8d9339e1f4822b3d93a97"},
    {"id": 6, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 32, "custom_str": "Test", "output_hex": "7a17c9714dbd6020f7c25af6050a4d30e87f1353ae1d583325e186e250e69545"},
    {"id": 7, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 32, "custom_str": "Test", "output_hex": "921dc6db693ceeba06d77899fbf526c7e4150540d60ae6a7919840e441eba1aa"},
    {"id": 8, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "", "output_len": 32, "custom_str": "KMAC test vector", "output_hex": "b6121c3da774aa0f86fcbe75af17788c624ca1cfd9e4bd85f7f81be99b77251f"},
    {"id": 9, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "", "output_len": 32, "custom_str": "KMAC test vector", "output_hex": "60c80e9ebf6655f879260ccfecdc690328e175433dac7dea57a0e31f18083a73"},
    {"id": 10, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 32, "custom_str": "", "output_hex": "efda38d40ef31f3726b388a1cfa6c1603ce7dd4b4982de631c91fe40801f6670"},
    {"id": 11, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 32, "custom_str": "", "output_hex": "ef41b581237afc205af13523b4c2c247be6fdfc533cf18ef3efe249fa0a813b2"},
    {"id": 12, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 32, "custom_str": "Test", "output_hex": "62caab19c7fad9f97cfd166ba1c55829245ef53d102cc5eb124636e50bbd261a"},
    {"id": 13, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 32, "custom_str": "Test", "output_hex": "911a919aca73bd69d08d0dec4fc527880c95a98c09d4503bf007c62c3abf159f"},
    {"id": 14, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "00", "output_len": 32, "custom_str": "KMAC test vector", "output_hex": "175b5efc8e2ee098bfd3f3a1c82de3ba6e1f4728041a0ec9b1282ff2426e2700"},
    {"id": 15, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "00", "output_len": 32, "custom_str": "KMAC test vector", "output_hex": "4344b552c35314e199f3b0072af3b1eb9fdd9c974be6e845247cc0ff5549ff84"},
    {"id": 16, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 32, "custom_str": "", "output_hex": "925bb722e503214db01e5c8f255def71d75a7985bdb7dd1646d3fcc13fe8f8cc"},
    {"id": 17, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "ff", "output_len": 32, "custom_str": "", "output_hex": "cd2f3f5fc62f4dc94916bb3f231c243a427fac73edf808d73faa8fa5741f69fb"},
    {"id": 18, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 32, "custom_str": "Test", "output_hex": "c9c4d7bd895c49f7c5562fd6af93b86464e07f57809f3675b8d60a2d0d6f315c"},
    {"id": 19, "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "data_hex": "ff", "output_len": 32, "custom_str": "Test", "output_hex": "03c70bb2ec52652a52a05da3e4918320f6c1bda9e839f8c060d5b9e42574491a"},
    {"id": 20, "key_hex": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "data_hex": "ff", "output_len": 32, "custom_str": "KMAC test vector", "output_hex": "54e64d0748bcec7e623e3216e2ccc99366243e90c26e190080b33f9fc0f81f84"},

]
