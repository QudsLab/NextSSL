# KAT/data/hash/bcrypt.py
# Known Answer Tests for bcrypt (Provos & Mazières 1999)

meta = {
    "group": "hash",
    "algorithm": "bcrypt",
    "source": "bcrypt Python library (implements OpenBSD Blowfish-based password hashing)",
    "source_ref": "https://pypi.org/project/bcrypt/",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "bcrypt is a password hashing scheme based on the Blowfish cipher, designed by "
        "Niels Provos and David Mazières in 1999.  The output includes the algorithm "
        "version ($2b$), cost factor, 22-character encoded salt, and 31-character hash.  "
        "Case fields: password_ascii, cost, salt (22 base64 chars), output (full hash string). "
        "All vectors use fixed salt '$2b$06$zWXQp.3sStHRMuD4fwbA5O' (cost=6). "
        "Computed and verified with the 'bcrypt' Python library."
    ),
}

# The fixed 22-character encoded salt used for all test cases
_SALT_PREFIX = "$2b$06$zWXQp.3sStHRMuD4fwbA5O"

cases = [
    {
        "id": 1,
        "password_ascii": "",
        "cost": 6,
        "salt_b64": "zWXQp.3sStHRMuD4fwbA5O",
        "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OY5BaL8RFlUQtnWF75JP0/YxAOAEyVk6",
    },
    {
        "id": 2,
        "password_ascii": "a",
        "cost": 6,
        "salt_b64": "zWXQp.3sStHRMuD4fwbA5O",
        "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Oa1qIywhm7Vpqh4o8qOocPq0hKEUFv4S",
    },
    {
        "id": 3,
        "password_ascii": "abc",
        "cost": 6,
        "salt_b64": "zWXQp.3sStHRMuD4fwbA5O",
        "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OnOS2Ts9gYOmKJN6TRkIP6ZC./QtA01S",
    },
    {
        "id": 4,
        "password_ascii": "password",
        "cost": 6,
        "salt_b64": "zWXQp.3sStHRMuD4fwbA5O",
        "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Ohr89uYxfbEjzNRdZKqJubY.2prR.dsS",
    },
    {
        "id": 5,
        "password_ascii": "Password1",
        "cost": 6,
        "salt_b64": "zWXQp.3sStHRMuD4fwbA5O",
        "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Oq62eOAYIDVHNkcgyCgx0NhPSMEV2sRu",
    },
    {"id": 6, "password_ascii": "hello", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5ODGpKRthG8o.pIt7dPkNWbElFO1fXu1G"},
    {"id": 7, "password_ascii": "world", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Ooz5o7fl4dJ.TEBgIiK.Jrmum87ScapO"},
    {"id": 8, "password_ascii": "test", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OpWk1m7qAN2ZTUV9VDLkJn6D5xILnD.q"},
    {"id": 9, "password_ascii": "hunter2", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OYgUVqIYub7kNSzJRAhEBQJCEbXoqyYy"},
    {"id": 10, "password_ascii": "letmein", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OakhH6lkhgInJuCx4DCAE/HDdVfXnHam"},
    {"id": 11, "password_ascii": "12345678", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OvVxhSalpnoclb1TJnvS2zYQPBCpGtrK"},
    {"id": 12, "password_ascii": "qwerty", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Okj5YFTyZMeyybM6DkBBXN4O0Xic5gpW"},
    {"id": 13, "password_ascii": "monkey", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OvLcfNdDm4/AY7FwrG7zWiErfusqWLVm"},
    {"id": 14, "password_ascii": "dragon", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5O0WeZPrIdMLca.RM/bjfmUC/vPQAtKom"},
    {"id": 15, "password_ascii": "admin", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5Os9mJpec4opADMfeQ2LvleO6g1qzL6ym"},
    {"id": 16, "password_ascii": "P@ssw0rd", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OHAa.Bo5V4dJpJ0TivM50vv9nAH6fkRO"},
    {"id": 17, "password_ascii": "secret!", "cost": 6, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$06$zWXQp.3sStHRMuD4fwbA5OjY95I/kj8mXaDv31.ahtep32RkPik0G"},
    {"id": 18, "password_ascii": "password", "cost": 4, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$04$zWXQp.3sStHRMuD4fwbA5OcZGxrWAF6UNQvNCf5.x4S12NlbLfoVW"},
    {"id": 19, "password_ascii": "password", "cost": 5, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$05$zWXQp.3sStHRMuD4fwbA5OGD00c4nwxboaL.M8SmzI1FWErboSa2C"},
    {"id": 20, "password_ascii": "a", "cost": 4, "salt_b64": "zWXQp.3sStHRMuD4fwbA5O", "output_str": "$2b$04$zWXQp.3sStHRMuD4fwbA5OQMT4mRkWxf.svelSeJphT/MsiWof4ze"},

]
