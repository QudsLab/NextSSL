# KAT provenance: ecdh-p521

Vectors were taken from the published file below (used verbatim, no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- `testvectors_v1/ecdh_secp521r1_ecpoint_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdh_secp521r1_ecpoint_test.json
  - sha256: 87aba8739c96de2bde8c75b60ffea09d0493192c4d9543d1d969e5e998931f35

Subset rule: none, the full file is stored (661 tests: 632 valid uncompressed, 0 valid compressed (expected to be rejected by this algorithm, see algo.toml notes), 28 invalid, 1 acceptable (compressed key, either outcome is allowed)).
