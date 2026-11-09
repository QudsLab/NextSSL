# KAT provenance: ecdsa-p256

Vectors were taken from the published files below by a script (no vector typed by hand, none produced by the crate under test). Signature verification (accept and reject) is replayed from Wycheproof and NIST ACVP.

Sources (downloaded 2026-11-08):
- `testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` (Project Wycheproof, used verbatim, full file)
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json
  - sha256: c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986
- `gen-val/json-files/ECDSA-SigVer-FIPS186-5/prompt.json`
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigVer-FIPS186-5/prompt.json
  - sha256: 2547cabd9a6006943ff611d4990fad18162b51a614cd2d7986769a3e94dee7e3
- `gen-val/json-files/ECDSA-SigVer-FIPS186-5/expectedResults.json`
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigVer-FIPS186-5/expectedResults.json
  - sha256: c4f2e21e9c6391a5349a81237b5c508466ce05f0d6eb6dbcecb17b458a6c5171
- `gen-val/json-files/ECDSA-SigGen-FIPS186-5/prompt.json`
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigGen-FIPS186-5/prompt.json
  - sha256: a07cfcf2e3bdbda1cbf82cefc6f38a2d0559ee8852b2f0276a200e0747b46744
- `gen-val/json-files/ECDSA-SigGen-FIPS186-5/expectedResults.json`
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigGen-FIPS186-5/expectedResults.json
  - sha256: 64ddfc8cdf1e4d693e888e40bab5d898aa4a6684812ed94371e90bb040559c6d
- `gen-val/json-files/ECDSA-KeyGen-FIPS186-5/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-KeyGen-FIPS186-5/internalProjection.json
  - sha256: 92ecd4c54e50dfb8f3f5a8e820d0380408727261d16e3035c2f6b5fee01827ca
- `gen-val/json-files/ECDSA-KeyVer-FIPS186-5/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-KeyVer-FIPS186-5/internalProjection.json
  - sha256: b8c47508838e8fb9f57eac1fbfda75a4f0b7d340e3a685bc667a19fc8c8c4aaa
- `gen-val/json-files/DetECDSA-SigGen-FIPS186-5/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/DetECDSA-SigGen-FIPS186-5/internalProjection.json
  - sha256: 161813f3e67428d2ec656ef63a179efa95cf649d321fa7f7ae9333c8f57cc59e

Subset rule: none. Wycheproof file is stored in full (262 tests: 173 valid, 89 invalid; every accept and reject case is checked). ACVP files contain only the groups for curve P-256 / SHA2-256 (the other curves and hashes are dropped), all their test cases kept.
