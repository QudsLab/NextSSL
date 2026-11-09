# KAT provenance: pbkdf2 (generic)

- vectors.json: for sha256 and sha512 the RFC 7914 + Wycheproof (C2SP/wycheproof @ d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9) vectors of the pbkdf2-hmac-sha256/512 ids (non-heavy ones re-checked with Python hashlib); for all ten hashes, Python hashlib.pbkdf2_hmac (OpenSSL), independent of the crate. Script: D:/Dev/kat_work/infra/pbkdf2_kat.py.
