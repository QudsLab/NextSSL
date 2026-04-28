# KAT/data/hash/nt.py
# Known Answer Tests for NT Hash (Windows NT LAN Manager hash)

meta = {
    "group": "hash",
    "algorithm": "NT",
    "source": "MS-NLMP specification — NT Hash is MD4 applied to UTF-16LE encoded password",
    "source_ref": "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "NT Hash = MD4(UTF-16LE(password)).  Used by Windows for password storage "
        "and NTLM authentication.  Vectors computed with Crypto.Hash.MD4 (pycryptodome) "
        "and Python's .encode('utf-16-le')."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "31d6cfe0d16ae931b73c59d7e0c089c0",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "186cb09181e2c2ecaac768c47c729904",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "e0fba38268d0ec66ef1cb452d5885e53",
    },
    {
        "id": 4,
        "input_ascii": "Password",
        "output_hex": "a4f49c406510bdcab6824ee7c30fd852",
    },
    {
        "id": 5,
        "input_ascii": "password",
        "output_hex": "8846f7eaee8fb117ad06bdd830b7586c",
    },
    {"id": 6, "input_ascii": "Administrator", "output_hex": "d144986c6122b1b1654ba39932465528"},
    {"id": 7, "input_ascii": "Welcome1", "output_hex": "cf3a5525ee9414229e66279623ed5c58"},
    {"id": 8, "input_ascii": "test123", "output_hex": "c5a237b7e9d8e708d8436b6148a25fa1"},
    {"id": 9, "input_ascii": "P@ssw0rd", "output_hex": "e19ccf75ee54e06b06a5907af13cef42"},
    {"id": 10, "input_ascii": "secret", "output_hex": "878d8014606cda29677a44efa1353fc7"},
    {"id": 11, "input_ascii": "hunter2", "output_hex": "6608e4bc7b2b7a5f77ce3573570775af"},
    {"id": 12, "input_ascii": "12345678", "output_hex": "259745cb123a52aa2e693aaacca2db52"},
    {"id": 13, "input_ascii": "letmein", "output_hex": "becedb42ec3c5c7f965255338be4453c"},
    {"id": 14, "input_ascii": "monkey", "output_hex": "f2477a144dff4f216ab81f2ac3e3207d"},
    {"id": 15, "input_ascii": "dragon", "output_hex": "f7eb9c06fafaa23c4bcf22ba6781c1e2"},
    {"id": 16, "input_ascii": "master", "output_hex": "6d3986e540a63647454a50e26477ef94"},
    {"id": 17, "input_ascii": "admin", "output_hex": "209c6174da490caeb422f3fa5a7ae634"},
    {"id": 18, "input_ascii": "qwerty", "output_hex": "2d20d252a479f485cdf5e171d93985bf"},
    {"id": 19, "input_ascii": "sunshine", "output_hex": "31c72c210ecc03d1eae94fa496069448"},
    {"id": 20, "input_ascii": "princess", "output_hex": "fb4bf3ddf37cf6494a9905541290cf51"},

]
