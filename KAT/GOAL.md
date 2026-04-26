# KAT GOAL — 126 Algorithm Coverage

All 126 algorithms sourced from ALGO.md.
Status markers: `[ ]` not started · `[~]` in progress · `[x]` done

Each completed entry links to its Python KAT file under `KAT/data/<group>/<algo>.py`.

Downloads go to `KAT/downloads/` → moved to `KAT/temp/` after the data is extracted into the .py file.

---

## Group 1 — Encoding (14)

| # | Algorithm | Status | Source |
|---|-----------|--------|--------|
| 1 | `base16` | [x] | RFC 4648 §8 |
| 2 | `base32` | [x] | RFC 4648 §6 |
| 3 | `base58` | [x] | Bitcoin Core / BIP |
| 4 | `base64` | [x] | RFC 4648 §4 |
| 5 | `base64url` | [x] | RFC 4648 §5 |
| 6 | `hex` | [x] | RFC 5234 / IANA |
| 7 | `ff70` | [x] | Internal spec |
| 8 | `base58check` | [x] | Bitcoin Base58Check |
| 9 | `base62` | [x] | Human-readable compact |
| 10 | `base85` | [x] | RFC 1924 / ASCII85 / ZeroMQ Z85 |
| 11 | `bech32` | [x] | BIP 173 / BIP 350 |
| 12 | `pem` | [x] | RFC 7468 |
| 13 | `crc32` | [x] | ISO 3309 / IEEE 802.3 |
| 14 | `crc64` | [x] | ECMA-182 |

---

## Group 2 — Hash / KDF (45)

| # | Algorithm | Status | Source |
|---|-----------|--------|--------|
| 15 | `blake2b` | [x] | RFC 7693 |
| 16 | `blake2s` | [x] | RFC 7693 |
| 17 | `blake3` | [x] | BLAKE3 paper |
| 18 | `sha224` | [x] | FIPS 180-4 |
| 19 | `sha256` | [x] | FIPS 180-4 |
| 20 | `sha384` | [x] | FIPS 180-4 |
| 21 | `sha512` | [x] | FIPS 180-4 |
| 22 | `sha512-224` | [x] | FIPS 180-4 |
| 23 | `sha512-256` | [x] | FIPS 180-4 |
| 24 | `sm3` | [x] | GM/T 0004-2012 |
| 25 | `has160` | [x] | KISA HAS-160 |
| 26 | `md2` | [x] | RFC 1319 |
| 27 | `md4` | [x] | RFC 1320 |
| 28 | `md5` | [x] | RFC 1321 |
| 29 | `nt` | [x] | MS NT Hash (MD4 of UTF-16LE) |
| 30 | `ripemd128` | [x] | ISO/IEC 10118-3 |
| 31 | `ripemd160` | [x] | ISO/IEC 10118-3 |
| 32 | `ripemd256` | [x] | RIPEMD-256 spec |
| 33 | `ripemd320` | [x] | RIPEMD-320 spec |
| 34 | `sha0` | [x] | FIPS 180 (original) |
| 35 | `sha1` | [x] | FIPS 180-4 |
| 36 | `whirlpool` | [x] | ISO/IEC 10118-3 |
| 37 | `argon2d` | [x] | RFC 9106 |
| 38 | `argon2i` | [x] | RFC 9106 |
| 39 | `argon2id` | [x] | RFC 9106 |
| 40 | `bcrypt` | [x] | Provos & Mazières 1999 |
| 41 | `catena` | [x] | Catena-v5 ref C (Catena-BRG, GCC/WSL) |
| 42 | `lyra2` | [x] | Lyra2-v3 ref C (N_COLS=16, GCC/WSL) |
| 43 | `scrypt` | [x] | RFC 7914 |
| 44 | `yescrypt` | [x] | pyescrypt 0.1.0 (CFFI, yescrypt ref C) |
| 45 | `balloon` | [x] | Boneh et al. 2016 |
| 46 | `pomelo` | [x] | POMELO-v3 official pomelo_testvectors.txt |
| 47 | `makwa` | [x] | Makwa spec |
| 48 | `keccak256` | [x] | Keccak submission |
| 49 | `sha3-224` | [x] | FIPS 202 |
| 50 | `sha3-256` | [x] | FIPS 202 |
| 51 | `sha3-384` | [x] | FIPS 202 |
| 52 | `sha3-512` | [x] | FIPS 202 |
| 53 | `shake128` | [x] | FIPS 202 |
| 54 | `shake256` | [x] | FIPS 202 |
| 55 | `skein256` | [x] | Skein spec |
| 56 | `skein512` | [x] | Skein spec |
| 57 | `skein1024` | [x] | Skein spec |
| 58 | `kmac128` | [x] | NIST SP 800-185 |
| 59 | `kmac256` | [x] | NIST SP 800-185 |

---

## Group 3 — Modern (32)

| # | Algorithm | Status | Source |
|---|-----------|--------|--------|
| 60 | `aes-cbc` | [x] | NIST SP 800-38A |
| 61 | `aes-gcm` | [x] | NIST SP 800-38D |
| 62 | `chacha20` | [x] | RFC 8439 |
| 63 | `hmac` | [x] | RFC 2202 / FIPS 198 |
| 64 | `poly1305` | [x] | RFC 8439 |
| 65 | `hkdf` | [x] | RFC 5869 |
| 66 | `pbkdf2` | [x] | RFC 8018 |
| 67 | `ed25519` | [x] | RFC 8032 |
| 68 | `x25519` | [x] | RFC 7748 |
| 69 | `p-256` | [x] | NIST FIPS 186-4 |
| 70 | `p-384` | [x] | NIST FIPS 186-4 |
| 71 | `p-521` | [x] | NIST FIPS 186-4 |
| 72 | `aes-ecb` | [x] | NIST SP 800-38A |
| 73 | `aes-ctr` | [x] | NIST SP 800-38A |
| 74 | `aes-cfb` | [x] | NIST SP 800-38A |
| 75 | `aes-ofb` | [x] | NIST SP 800-38A |
| 76 | `aes-xts` | [x] | NIST SP 800-38E |
| 77 | `aes-fpe` | [x] | NIST SP 800-38G (FF3-1) |
| 78 | `aes-kw` | [x] | NIST SP 800-38F |
| 79 | `3des-cbc` | [x] | NIST SP 800-67 |
| 80 | `aes-ccm` | [x] | NIST SP 800-38C |
| 81 | `aes-eax` | [x] | Bellare et al. |
| 82 | `aes-gcm-siv` | [x] | RFC 8452 |
| 83 | `aes-ocb` | [x] | RFC 7253 |
| 84 | `aes-siv` | [x] | RFC 5297 |
| 85 | `chacha20-poly1305` | [x] | RFC 8439 |
| 86 | `aes-cmac` | [x] | NIST SP 800-38B |
| 87 | `siphash` | [x] | SipHash paper |
| 88 | `ed448` | [x] | RFC 8032 |
| 89 | `x448` | [x] | RFC 7748 |
| 90 | `rsa` | [x] | PKCS#1 / RFC 8017 |
| 91 | `sm2` | [x] | GM/T 0003 |

---

## Group 4 — PQC (35)

| # | Algorithm | Status | Source |
|---|-----------|--------|--------|
| 92 | `ml-kem-512` | [ ] | NIST FIPS 203 |
| 93 | `ml-kem-768` | [ ] | NIST FIPS 203 |
| 94 | `ml-kem-1024` | [ ] | NIST FIPS 203 |
| 95 | `ml-dsa-44` | [ ] | NIST FIPS 204 |
| 96 | `ml-dsa-65` | [ ] | NIST FIPS 204 |
| 97 | `ml-dsa-87` | [ ] | NIST FIPS 204 |
| 98 | `falcon-512` | [ ] | NIST PQC / Falcon spec |
| 99 | `falcon-1024` | [ ] | NIST PQC / Falcon spec |
| 100 | `falcon-padded-512` | [ ] | Falcon spec |
| 101 | `falcon-padded-1024` | [ ] | Falcon spec |
| 102 | `hqc-128` | [ ] | HQC spec |
| 103 | `hqc-192` | [ ] | HQC spec |
| 104 | `hqc-256` | [ ] | HQC spec |
| 105 | `mceliece-348864` | [ ] | NIST PQC |
| 106 | `mceliece-348864f` | [ ] | NIST PQC |
| 107 | `mceliece-460896` | [ ] | NIST PQC |
| 108 | `mceliece-460896f` | [ ] | NIST PQC |
| 109 | `mceliece-6688128` | [ ] | NIST PQC |
| 110 | `mceliece-6688128f` | [ ] | NIST PQC |
| 111 | `mceliece-6960119` | [ ] | NIST PQC |
| 112 | `mceliece-6960119f` | [ ] | NIST PQC |
| 113 | `mceliece-8192128` | [ ] | NIST PQC |
| 114 | `mceliece-8192128f` | [ ] | NIST PQC |
| 115 | `sphincs-sha2-128f` | [ ] | NIST FIPS 205 |
| 116 | `sphincs-sha2-128s` | [ ] | NIST FIPS 205 |
| 117 | `sphincs-sha2-192f` | [ ] | NIST FIPS 205 |
| 118 | `sphincs-sha2-192s` | [ ] | NIST FIPS 205 |
| 119 | `sphincs-sha2-256f` | [ ] | NIST FIPS 205 |
| 120 | `sphincs-sha2-256s` | [ ] | NIST FIPS 205 |
| 121 | `sphincs-shake-128f` | [ ] | NIST FIPS 205 |
| 122 | `sphincs-shake-128s` | [ ] | NIST FIPS 205 |
| 123 | `sphincs-shake-192f` | [ ] | NIST FIPS 205 |
| 124 | `sphincs-shake-192s` | [ ] | NIST FIPS 205 |
| 125 | `sphincs-shake-256f` | [ ] | NIST FIPS 205 |
| 126 | `sphincs-shake-256s` | [ ] | NIST FIPS 205 |

---

## Progress

- Encoding: 14 / 14  ✓
- Hash/KDF: 45 / 45  ✓ (all populated: catena/lyra2/pomelo via ref C builds; yescrypt via pyescrypt)
- Modern: 32 / 32  ✓
- PQC: 0 / 35  (deliberately deferred)
- **Total: 91 / 126** (126 files created; 35 PQC pending)

---

## Conventions

- KAT file location: `KAT/data/<group>/<algo>.py`
- Downloads (raw NIST/spec KAT files): `KAT/downloads/<algo>/`
- After extraction, move downloads to `KAT/temp/<algo>/`
- `input_hex` is lowercase hex of raw input bytes
- `output_hex` is lowercase hex of the digest/ciphertext/encoded bytes
- String inputs use `input_ascii` key instead of `input_hex`
- Encoding KATs use `input_ascii` → `output_ascii` (or `output_hex` for binary outputs)
