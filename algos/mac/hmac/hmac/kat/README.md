# KAT provenance: hmac (generic)

- rfc4231.json: parsed from https://www.rfc-editor.org/rfc/rfc4231.txt (sha256 `72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b`), HMAC-SHA-224/256/384/512 test cases 1-7 (TC5 is the 128-bit truncated tag); cross-checked with Python hmac (script D:/Dev/kat_work/infra/hmac_kat.py).
- py-hmac.json: Python 3 hmac + hashlib for all ten hashes, key lengths around each block size. Independent implementation (not the crate under test).
- wycheproof_hmac_*_test.json: C2SP/wycheproof @ d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9 testvectors_v1, copied verbatim from the sibling hmac-* ids (sha256, sha512, sha3-256/384/512).
- sha512-224, sha512-256 and sha3-224 have Python vectors only (no RFC or Wycheproof file exists for them).
