# KAT provenance: slh-dsa-sha2-128s

NIST ACVP-Server SLH-DSA vectors (FIPS 205), values verbatim, selected by a script (no vector typed by hand, none produced by the crate under test).

Sources (downloaded 2026-11-08):
- `gen-val/json-files/SLH-DSA-keyGen-FIPS205/prompt.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/prompt.json
  - sha256: bce170976f257ee3dfc8c54ea46722ccb553539847daa6d8048f0216cc28b51c
- `gen-val/json-files/SLH-DSA-keyGen-FIPS205/expectedResults.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/expectedResults.json
  - sha256: f35f74b6676d6b369c87e88c36698f28c14d5929d31e507d910288c69258afee
- `gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json
  - sha256: afa673eacdf0aec53512a159159b7632684adfcd0d88f8640a7f6f5796aacdc8
- `gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json
  - sha256: 71e8e0f7e4b0cfd1747314299204d9d4d50968d200a4ae873921eaa7aabeaad1
- `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` (NIST ACVP-Server)
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
  - sha256: a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792

Subset rule (the full files are 30-38 MB each because SLH-DSA signatures are up to 50 KB): parameter set SLH-DSA-SHA2-128s, external interface / pure (non pre-hash) groups only. keyGen: the first 5 test cases of the group. sigGen: the first test case of the deterministic group and of the hedged group (2 signatures). sigVer: within the group (14 cases) the first case of every distinct reason: valid signature, modified message, modified signature R / SIGFORS / SIGHT, signature too small, signature too large; 1 pass and 6 reject cases. The internal-interface and HashSLH-DSA groups are not used.
