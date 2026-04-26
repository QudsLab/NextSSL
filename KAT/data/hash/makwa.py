# KAT/data/hash/makwa.py
# Known Answer Tests for Makwa Password Hashing Scheme

meta = {
    "group": "hash",
    "algorithm": "Makwa",
    "source": "Makwa specification v1.0 (2014) — Python makwa library",
    "source_ref": "http://www.bolet.org/makwa/makwa-spec-20140422.pdf",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Makwa is a password-hashing function based on modular squaring in Z/nZ. "
        "Vectors use the official 2048-bit test modulus from the spec "
        "(n = 0xC22C40BB...CEF761, first 8 bytes of SHA-256(n) = +RK3n5jz7gs in base64url). "
        "The spec test salt is 0xC72703C22A96D9992F3DEA876497E392 (16 bytes). "
        "Case fields: password_ascii, work_factor, post_hash_len, pre_hash, output_str. "
        "output_str is the self-contained Makwa token: "
        "  <modulus_id>_<params>_<salt_b64>_<hash_b64> "
        "where modulus_id='+RK3n5jz7gs', salt='xycDwiqW2ZkvPeqHZJfjkg' (spec salt). "
        "Vectors can be verified with makwa.checkpw(password, output_str)."
    ),
}

cases = [
    {
        "id": 1,
        "password_ascii": "",
        "work_factor": 256,
        "post_hash_len": 12,
        "pre_hash": False,
        "output_str": "+RK3n5jz7gs_s207_xycDwiqW2ZkvPeqHZJfjkg_x2GYB6rzKcQD2axO",
    },
    {
        "id": 2,
        "password_ascii": "a",
        "work_factor": 256,
        "post_hash_len": 12,
        "pre_hash": False,
        "output_str": "+RK3n5jz7gs_s207_xycDwiqW2ZkvPeqHZJfjkg_wn+tqraTQEHc6pOK",
    },
    {
        "id": 3,
        "password_ascii": "password",
        "work_factor": 256,
        "post_hash_len": 12,
        "pre_hash": False,
        "output_str": "+RK3n5jz7gs_s207_xycDwiqW2ZkvPeqHZJfjkg_mzUFm6F5FPkMvrek",
    },
    {
        "id": 4,
        "password_ascii": "3.14159265358979323846",
        "work_factor": 256,
        "post_hash_len": 12,
        "pre_hash": False,
        "output_str": "+RK3n5jz7gs_s207_xycDwiqW2ZkvPeqHZJfjkg_NEyVPRzP0BtNUZuF",
    },
    {
        "id": 5,
        "password_ascii": "3.14159265358979323846",
        "work_factor": 4096,
        "post_hash_len": 0,
        "pre_hash": False,
        "output_str": (
            "+RK3n5jz7gs_n211_xycDwiqW2ZkvPeqHZJfjkg_"
            "QdFa4bU1kGsFRrKc7d6dpsW4trhsY1+thzvn2A/pIOd49pdr5LILTy+dyS6RDmNXXBd1mTe4xN91icgCKUUYsz"
            "+1lab6L0Ep+24hd8RgRyI59tUqW4XJcYGL4Lkp4dMLBnwD7RaFLs1SCxSz4zmRKiCtDpuIXbf6mIMDSJxAjCM"
            "vaHai7gKcUxwmV5nxL8qHWloQsuB/dXX/Tv+xvr+EleMP1DXJsCSsWMx0qZe2O70gmNJvn2z4qbYAZXvFiTvYT"
            "4U+rRn5kOMRWjyzqluE6n6GSbyQmgKn+eGNsFOqhYRTAbt8ljbsh8iuy7OkvdbkEy+/G4mmndam3jX+55OZQA"
        ),
    },
]
