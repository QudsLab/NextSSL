# KAT provenance: cbc-mac

- vectors.json: pycryptodome AES-CBC with zero IV, MAC = last ciphertext block (script D:/Dev/kat_work/infra/cbcmac_kat.py). Independent of the crate under test. No published standalone CBC-MAC vector set was found (FIPS 113 is withdrawn); CBC mode itself is covered by NIST SP 800-38A, which pycryptodome reproduces.
