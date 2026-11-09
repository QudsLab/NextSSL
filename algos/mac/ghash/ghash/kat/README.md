# KAT provenance: ghash

- vectors.json: Python reference of NIST SP 800-38D algorithm 1 (GF(2^128) multiplication), validated against pycryptodome AES-GCM on random cases before use (script D:/Dev/kat_work/infra/ghash_kat.py). No standalone published GHASH vector set exists; the crate's own tests are not used.
