# KAT provenance: aes-256-gcm-siv

Vectors in this folder were extracted from the published files below by a script (no vector typed by hand, none produced by the upstream crate under test).

Sources:
- ACVP-AES-GCM-SIV-1.0.internalProjection.json
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-SIV-1.0/internalProjection.json
  - sha256: a355e8dd185700f046a802511af5928fd9f04ffd792cab77ab60122a946036cd
  - downloaded: 2026-11-08
  - commit 975de31eb83d87039ec88934fdc47d8c312b892d
- aes_gcm_siv_test.json
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_siv_test.json
  - sha256: d96e4f8c0db1a5e3b395907120f9d417d599507e7a08a1f60babff09ae276a8d
  - downloaded: 2026-11-08
  - C2SP/wycheproof commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9

<!-- kat1:begin -->
## Published vectors added by kat1 (D:\Dev\kat_work\kat1\gen.py)

### acvp-gcm-siv.json (10 vectors, at most 10 kept per parameter set)
- independence: independent (RFC test vectors)
- source file: `RFC 8452 appendix C.2`
  - URL: https://www.rfc-editor.org/rfc/rfc8452.txt
  - sha256 of the file used: `ca48ec466b401ce5d68d6d1628127a1800adcc16f2573646aaa3d7df284d3c17`

<!-- kat1:end -->
