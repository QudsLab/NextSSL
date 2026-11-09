# KAT provenance: ed448

Vectors were extracted from the published files below by a script (no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- RFC 8032 (section 7.4, Ed448)
  - URL: https://www.rfc-editor.org/rfc/rfc8032.txt
  - sha256: ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3
- `testvectors_v1/ed448_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ed448_test.json
  - sha256: 3b3c7995853deb2fbbb49fba0fd292f314dc081f9154bd33252f294ca211289a
- `gen-val/json-files/EDDSA-KeyGen-1.0/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/EDDSA-KeyGen-1.0/internalProjection.json
  - sha256: 8847fbe4a18c980dab179c5dce182ebd0f9f990f409fa359665a8e67bee33fea
- `gen-val/json-files/EDDSA-SigGen-1.0/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/EDDSA-SigGen-1.0/internalProjection.json
  - sha256: 794d58fb39f08de4f852d63cb98b95c39bcc38ea42c7d42d09e92c15dadd5d81
- `gen-val/json-files/EDDSA-SigVer-1.0/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/EDDSA-SigVer-1.0/internalProjection.json
  - sha256: 8556b9c48ef7ff209a9f866ed83e3c3881cfdd3c4c1ee1abe2602da69c1e97b0

Subset rule: none. RFC 8032 section 7.4 vectors are all included; the Wycheproof file is stored in full (87 tests: 17 valid, 70 invalid). ACVP: only the ED-448 groups without pre-hash.
