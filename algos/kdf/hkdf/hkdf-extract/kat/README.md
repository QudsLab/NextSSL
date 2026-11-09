# KAT provenance: hkdf (generic)

- vectors.json: RFC 5869 appendix A test cases 1-3 (SHA-256; from the hkdf-sha256 KAT, re-derived and checked by an independent Python HKDF) plus Python 3 hmac/hashlib HKDF reference vectors for all ten hashes (script D:/Dev/kat_work/infra/hkdf_kat.py). The same file is used by hkdf-extract (prk_hex) and hkdf-expand (prk_hex -> out_hex).
