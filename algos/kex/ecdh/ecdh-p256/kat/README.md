# KAT provenance: ecdh-p256

Vectors were taken from the published file below (used verbatim, no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- `testvectors_v1/ecdh_secp256r1_ecpoint_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdh_secp256r1_ecpoint_test.json
  - sha256: 648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886

Subset rule: none, the full file is stored (355 tests: 330 valid uncompressed, 0 valid compressed (expected to be rejected by this algorithm, see algo.toml notes), 24 invalid, 1 acceptable (compressed key, either outcome is allowed)).
