# KAT provenance: ecdh-p384

Vectors were taken from the published file below (used verbatim, no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- `testvectors_v1/ecdh_secp384r1_ecpoint_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdh_secp384r1_ecpoint_test.json
  - sha256: ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3

Subset rule: none, the full file is stored (790 tests: 771 valid uncompressed, 0 valid compressed (expected to be rejected by this algorithm, see algo.toml notes), 18 invalid, 1 acceptable (compressed key, either outcome is allowed)).
