# KAT provenance: x448

Vectors were extracted from the published files below by a script (no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- RFC 7748 (sections 5.2 and 6.2, X448)
  - URL: https://www.rfc-editor.org/rfc/rfc7748.txt
  - sha256: 279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3
- `testvectors_v1/x448_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/x448_test.json
  - sha256: 0f8f7199dbd47d1805cb9b13dfb29c207406bc786827bfd9ba7b73374b830fe5

Subset rule: none. The Wycheproof file is stored in full (510 tests; 487 compare against the published shared secret, 23 are zero-secret or wrong-length-key cases that must be rejected). The RFC 7748 1,000,000-iteration value is recorded but not run.
