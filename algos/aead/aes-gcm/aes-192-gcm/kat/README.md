# KAT provenance: aes-192-gcm

Vectors in this folder were extracted from the published files below by a script (no vector typed by hand, none produced by the upstream crate under test).

Sources:
- ACVP-AES-GCM-1.0.internalProjection.json
  - URL: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-1.0/internalProjection.json
  - sha256: 0703118c1f751f32cdb8d32b8e54d5f80eb9bbe7bb99b83a6b0221cb40b34f0e
  - downloaded: 2026-11-08
  - commit 975de31eb83d87039ec88934fdc47d8c312b892d
- aes_gcm_test.json
  - URL: https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_test.json
  - sha256: 985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7
  - downloaded: 2026-11-08
  - C2SP/wycheproof commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9

<!-- kat1:begin -->
## Published vectors added by kat1 (D:\Dev\kat_work\kat1\gen.py)

### acvp-gcm.json (10 vectors, at most 10 kept per parameter set)
- independence: independent (Wycheproof, generated outside this repo)
- source file: `testvectors_v1/aes_gcm_test.json`
  - URL: https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_test.json
  - sha256 of the file used: `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7`

<!-- kat1:end -->
