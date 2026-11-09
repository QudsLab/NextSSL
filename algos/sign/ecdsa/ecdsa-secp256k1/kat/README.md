# KAT provenance: ecdsa-secp256k1

Vectors were taken from the published files below by a script (no vector typed by hand, none produced by the crate under test). Signature verification (accept and reject) is replayed from Wycheproof.

Sources (downloaded 2026-11-08):
- `testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json
  - sha256: 7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2

Subset rule: none. Wycheproof file stored in full (252 tests). There is no NIST ACVP vector set for secp256k1.
