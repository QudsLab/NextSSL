# Complete algorithm inventory (post-0004 flat hash layout)

This records the named algorithm surface in the NextSSL (8 groups, 250 total algorithm surfaces).

Status colors: blue means current inventory surface; green means planned surface to add or expose.

## 1. Encoding algorithms (14)

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![base16](https://img.shields.io/badge/base16-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 2 | ![base32](https://img.shields.io/badge/base32-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 3 | ![base58](https://img.shields.io/badge/base58-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 4 | ![base64](https://img.shields.io/badge/base64-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 5 | ![base64url](https://img.shields.io/badge/base64url-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 6 | ![hex](https://img.shields.io/badge/hex-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 7 | ![ff70](https://img.shields.io/badge/ff70-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 8 | ![base58check](https://img.shields.io/badge/base58check-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 9 | ![base62](https://img.shields.io/badge/base62-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 10 | ![base85](https://img.shields.io/badge/base85-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 11 | ![bech32](https://img.shields.io/badge/bech32-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 12 | ![pem](https://img.shields.io/badge/pem-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Representation |
| 13 | ![crc32](https://img.shields.io/badge/crc32-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Checksum |
| 14 | ![crc64](https://img.shields.io/badge/crc64-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![encoding/checksum](https://img.shields.io/badge/encoding%2Fchecksum-type-2f7d4f) | Checksum |

Notes:

- `base16` and `hex` exist as separate named modules/surfaces in the tree even though they are the same radix family.
- `crc32` and `crc64` sit in the encoding surface of `src/root/modern/root_modern.h`, but they are checksum helpers rather than text encodings.

### 2. Hash / KDF-hash algorithms (59)

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![blake2b](https://img.shields.io/badge/blake2b-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 2 | ![blake2s](https://img.shields.io/badge/blake2s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 3 | ![blake3](https://img.shields.io/badge/blake3-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 4 | ![sha224](https://img.shields.io/badge/sha224-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 5 | ![sha256](https://img.shields.io/badge/sha256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 6 | ![sha384](https://img.shields.io/badge/sha384-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 7 | ![sha512](https://img.shields.io/badge/sha512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 8 | ![sha512-224](https://img.shields.io/badge/sha512--224-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 9 | ![sha512-256](https://img.shields.io/badge/sha512--256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 10 | ![sm3](https://img.shields.io/badge/sm3-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 11 | ![has160](https://img.shields.io/badge/has160-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 12 | ![md2](https://img.shields.io/badge/md2-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 13 | ![md4](https://img.shields.io/badge/md4-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 14 | ![md5](https://img.shields.io/badge/md5-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 15 | ![nt](https://img.shields.io/badge/nt-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 16 | ![ripemd128](https://img.shields.io/badge/ripemd128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 17 | ![ripemd160](https://img.shields.io/badge/ripemd160-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 18 | ![ripemd256](https://img.shields.io/badge/ripemd256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 19 | ![ripemd320](https://img.shields.io/badge/ripemd320-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 20 | ![sha0](https://img.shields.io/badge/sha0-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 21 | ![sha1](https://img.shields.io/badge/sha1-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 22 | ![tiger](https://img.shields.io/badge/tiger-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 23 | ![whirlpool](https://img.shields.io/badge/whirlpool-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 24 | ![argon2d](https://img.shields.io/badge/argon2d-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 25 | ![argon2i](https://img.shields.io/badge/argon2i-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 26 | ![argon2id](https://img.shields.io/badge/argon2id-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 27 | ![bcrypt](https://img.shields.io/badge/bcrypt-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 28 | ![catena](https://img.shields.io/badge/catena-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 29 | ![lyra2](https://img.shields.io/badge/lyra2-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 30 | ![scrypt](https://img.shields.io/badge/scrypt-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 31 | ![yescrypt](https://img.shields.io/badge/yescrypt-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 32 | ![balloon](https://img.shields.io/badge/balloon-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 33 | ![pomelo](https://img.shields.io/badge/pomelo-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 34 | ![makwa](https://img.shields.io/badge/makwa-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Password KDF |
| 35 | ![keccak256](https://img.shields.io/badge/keccak256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 36 | ![sha3-224](https://img.shields.io/badge/sha3--224-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 37 | ![sha3-256](https://img.shields.io/badge/sha3--256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 38 | ![sha3-384](https://img.shields.io/badge/sha3--384-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 39 | ![sha3-512](https://img.shields.io/badge/sha3--512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 40 | ![shake](https://img.shields.io/badge/shake-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 41 | ![shake128](https://img.shields.io/badge/shake128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 42 | ![shake256](https://img.shields.io/badge/shake256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 43 | ![cshake](https://img.shields.io/badge/cshake-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 44 | ![kmac](https://img.shields.io/badge/kmac-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 45 | ![kmac128](https://img.shields.io/badge/kmac128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 46 | ![kmac256](https://img.shields.io/badge/kmac256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 47 | ![parallelhash](https://img.shields.io/badge/parallelhash-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 48 | ![tuplehash](https://img.shields.io/badge/tuplehash-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | XOF / SHA-3 family |
| 49 | ![skein256](https://img.shields.io/badge/skein256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 50 | ![skein512](https://img.shields.io/badge/skein512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 51 | ![skein1024](https://img.shields.io/badge/skein1024-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | Digest |
| 52 | ![kmacxof128](https://img.shields.io/badge/kmacxof128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | KMAC128 in XOF mode |
| 53 | ![kmacxof256](https://img.shields.io/badge/kmacxof256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | KMAC256 in XOF mode |
| 54 | ![kangarootwelve](https://img.shields.io/badge/kangarootwelve-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | KangarooTwelve tree hash / XOF |
| 55 | ![marsupilami14](https://img.shields.io/badge/marsupilami14-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | MarsupilamiFourteen tree hash / XOF |
| 56 | ![parallelhash128](https://img.shields.io/badge/parallelhash128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | ParallelHash with 128-bit security strength |
| 57 | ![parallelhash256](https://img.shields.io/badge/parallelhash256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | ParallelHash with 256-bit security strength |
| 58 | ![tuplehash128](https://img.shields.io/badge/tuplehash128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | TupleHash with 128-bit security strength |
| 59 | ![tuplehash256](https://img.shields.io/badge/tuplehash256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![hash/KDF-hash](https://img.shields.io/badge/hash%2FKDF--hash-type-6d5796) | TupleHash with 256-bit security strength |

- Plan decision: keep the concrete algorithm count as the source-of-truth inventory count; do not count family selector names as additional algorithms unless an explicit variant surface is listed.

**Hash alias note:**

- `nthash` -> `nt`
- `sha512/224` -> `sha512-224`
- `sha512/256` -> `sha512-256`

### 3. Modern algorithms (84)

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![aes-cbc](https://img.shields.io/badge/aes--cbc-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Symmetric / AEAD |
| 2 | ![aes-gcm](https://img.shields.io/badge/aes--gcm-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Symmetric / AEAD |
| 3 | ![chacha20](https://img.shields.io/badge/chacha20-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Stream cipher |
| 4 | ![hmac](https://img.shields.io/badge/hmac-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | MAC |
| 5 | ![poly1305](https://img.shields.io/badge/poly1305-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | MAC |
| 6 | ![hkdf](https://img.shields.io/badge/hkdf-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | KDF |
| 7 | ![pbkdf2](https://img.shields.io/badge/pbkdf2-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | KDF |
| 8 | ![ed25519](https://img.shields.io/badge/ed25519-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Signature |
| 9 | ![x25519](https://img.shields.io/badge/x25519-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Key agreement |
| 10 | ![p-256](https://img.shields.io/badge/p--256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Curve |
| 11 | ![p-384](https://img.shields.io/badge/p--384-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Curve |
| 12 | ![p-521](https://img.shields.io/badge/p--521-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Curve |
| 13 | ![aes-ecb](https://img.shields.io/badge/aes--ecb-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Block mode |
| 14 | ![aes-ctr](https://img.shields.io/badge/aes--ctr-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Block mode |
| 15 | ![aes-cfb](https://img.shields.io/badge/aes--cfb-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Block mode |
| 16 | ![aes-ofb](https://img.shields.io/badge/aes--ofb-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Block mode |
| 17 | ![aes-xts](https://img.shields.io/badge/aes--xts-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Disk mode |
| 18 | ![aes-fpe](https://img.shields.io/badge/aes--fpe-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | FPE FF1 |
| 19 | ![aes-kw](https://img.shields.io/badge/aes--kw-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Key wrap |
| 20 | ![3des-cbc](https://img.shields.io/badge/3des--cbc-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Legacy block mode |
| 21 | ![aes-ccm](https://img.shields.io/badge/aes--ccm-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEAD |
| 22 | ![aes-eax](https://img.shields.io/badge/aes--eax-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEAD |
| 23 | ![aes-gcm-siv](https://img.shields.io/badge/aes--gcm--siv-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Misuse-resistant AEAD |
| 24 | ![aes-ocb](https://img.shields.io/badge/aes--ocb-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEAD |
| 25 | ![aes-siv](https://img.shields.io/badge/aes--siv-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Misuse-resistant AEAD |
| 26 | ![chacha20-poly1305](https://img.shields.io/badge/chacha20--poly1305-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEAD |
| 27 | ![aes-cmac](https://img.shields.io/badge/aes--cmac-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | MAC |
| 28 | ![siphash](https://img.shields.io/badge/siphash-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | MAC |
| 29 | ![ed448](https://img.shields.io/badge/ed448-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | EdDSA over Ed448; keep separate from x448 and curve448 |
| 30 | ![x448](https://img.shields.io/badge/x448-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | X448 Diffie-Hellman key agreement; keep separate from curve448 |
| 31 | ![curve448](https://img.shields.io/badge/curve448-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Curve448 field/curve surface; currently may be handled through x448 code path, but... |
| 32 | ![rsa](https://img.shields.io/badge/rsa-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Signature / public-key |
| 33 | ![sm2](https://img.shields.io/badge/sm2-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Conditional SM2 public-key |
| 34 | ![aes-cbc-cs](https://img.shields.io/badge/aes--cbc--cs-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AES-CBC with ciphertext stealing (CS1/CS2/CS3 variants, SP 800-38A) |
| 35 | ![aes-fpe-ff3](https://img.shields.io/badge/aes--fpe--ff3-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AES Format-Preserving Encryption FF3-1 mode (SP 800-38G) |
| 36 | ![aes-gmac](https://img.shields.io/badge/aes--gmac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | GCM with empty plaintext; produces authentication tag only (SP 800-38D) |
| 37 | ![aes-kwp](https://img.shields.io/badge/aes--kwp-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AES Key Wrap with Padding (SP 800-38F) |
| 38 | ![aes-xpn](https://img.shields.io/badge/aes--xpn-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AES-GCM Extended Packet Numbering for MACsec (IEEE 802.1AEbw) |
| 39 | ![dsa](https://img.shields.io/badge/dsa-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Classical Digital Signature Algorithm (FIPS 186-4) |
| 40 | ![det-ecdsa](https://img.shields.io/badge/det--ecdsa-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Deterministic ECDSA per RFC 6979 / FIPS 186-5 |
| 41 | ![kda-onestep](https://img.shields.io/badge/kda--onestep-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | One-Step Key Derivation (SP 800-56C) |
| 42 | ![kda-twostep](https://img.shields.io/badge/kda--twostep-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Two-Step Key Derivation (SP 800-56C) |
| 43 | ![kdf-sp800-108](https://img.shields.io/badge/kdf--sp800--108-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Counter/Feedback/Pipeline KDF (SP 800-108r1) |
| 44 | ![kdf-tls12](https://img.shields.io/badge/kdf--tls12-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | TLS 1.2 PRF key derivation (RFC 7627) |
| 45 | ![kdf-tls13](https://img.shields.io/badge/kdf--tls13-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | TLS 1.3 HKDF-based key schedule (RFC 8446) |
| 46 | ![kdf-ssh](https://img.shields.io/badge/kdf--ssh-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | SSH key derivation (RFC 4253) |
| 47 | ![kdf-ike](https://img.shields.io/badge/kdf--ike-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | IKEv1/IKEv2 KDF |
| 48 | ![kdf-srtp](https://img.shields.io/badge/kdf--srtp-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | SRTP key derivation (RFC 3711) |
| 49 | ![kdf-ansi-x963](https://img.shields.io/badge/kdf--ansi--x963-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | ANSI X9.63 KDF |
| 50 | ![aes-pmac](https://img.shields.io/badge/aes--pmac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Parallelizable AES-based message authentication code |
| 51 | ![xcbc-mac](https://img.shields.io/badge/xcbc--mac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AES-XCBC-MAC legacy MAC construction |
| 52 | ![vmac](https://img.shields.io/badge/vmac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | High-speed universal-hash message authentication code |
| 53 | ![umac](https://img.shields.io/badge/umac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Universal-hash message authentication code |
| 54 | ![dh](https://img.shields.io/badge/dh-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Finite-field Diffie-Hellman key exchange |
| 55 | ![ecdh](https://img.shields.io/badge/ecdh-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Elliptic-curve Diffie-Hellman key exchange |
| 56 | ![ecmqv](https://img.shields.io/badge/ecmqv-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Elliptic-curve MQV authenticated key agreement |
| 57 | ![x3dh](https://img.shields.io/badge/x3dh-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Extended Triple Diffie-Hellman messaging key agreement |
| 58 | ![hpke](https://img.shields.io/badge/hpke-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Hybrid Public Key Encryption (RFC 9180) |
| 59 | ![ecies](https://img.shields.io/badge/ecies-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Elliptic Curve Integrated Encryption Scheme |
| 60 | ![ecdsa](https://img.shields.io/badge/ecdsa-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Standard Elliptic Curve Digital Signature |
| 61 | ![rsa-pss](https://img.shields.io/badge/rsa--pss-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | RSA Probabilistic Signature Scheme |
| 62 | ![rsa-pkcs1v15](https://img.shields.io/badge/rsa--pkcs1v15-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | RSA PKCS #1 v1.5 signature / encryption |
| 63 | ![ecdsa-recoverable](https://img.shields.io/badge/ecdsa--recoverable-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Recoverable ECDSA signatures used in secp256k1 ecosystems |
| 64 | ![sr25519](https://img.shields.io/badge/sr25519-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Schnorrkel / Ristretto255 signature |
| 65 | ![secp256k1](https://img.shields.io/badge/secp256k1-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Koblitz curve used in Bitcoin and related systems |
| 66 | ![concat-kdf](https://img.shields.io/badge/concat--kdf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Concatenation KDF used by NIST / JOSE / ECIES profiles |
| 67 | ![x942-kdf](https://img.shields.io/badge/x942--kdf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | ANSI X9.42 KDF used in CMS / PKCS ecosystems |
| 68 | ![noise-kdf](https://img.shields.io/badge/noise--kdf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Noise Protocol Framework KDF |
| 69 | ![bip32-kdf](https://img.shields.io/badge/bip32--kdf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | BIP32 hierarchical deterministic wallet KDF |
| 70 | ![slip10](https://img.shields.io/badge/slip10-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | SLIP-0010 deterministic key hierarchy derivation |
| 71 | ![sskdf](https://img.shields.io/badge/sskdf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Single-step KDF from SP 800-56C |
| 72 | ![hkdf-expand-label](https://img.shields.io/badge/hkdf--expand--label-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | TLS 1.3 labeled HKDF expansion helper |
| 73 | ![xchacha20](https://img.shields.io/badge/xchacha20-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Extended-nonce ChaCha20 stream cipher |
| 74 | ![salsa20](https://img.shields.io/badge/salsa20-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Salsa20 stream cipher |
| 75 | ![xsalsa20](https://img.shields.io/badge/xsalsa20-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Extended-nonce Salsa20 stream cipher |
| 76 | ![hc128](https://img.shields.io/badge/hc128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | HC-128 stream cipher |
| 77 | ![hc256](https://img.shields.io/badge/hc256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | HC-256 stream cipher |
| 78 | ![rabbit](https://img.shields.io/badge/rabbit-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Rabbit stream cipher |
| 79 | ![sosemanuk](https://img.shields.io/badge/sosemanuk-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | SOSEMANUK stream cipher |
| 80 | ![xchacha20-poly1305](https://img.shields.io/badge/xchacha20--poly1305-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Extended-nonce ChaCha20-Poly1305 AEAD |
| 81 | ![aegis128l](https://img.shields.io/badge/aegis128l-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEGIS-128L AEAD |
| 82 | ![aegis256](https://img.shields.io/badge/aegis256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | AEGIS-256 AEAD |
| 83 | ![deoxys-ii](https://img.shields.io/badge/deoxys--ii-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Misuse-resistant AEAD |
| 84 | ![isap](https://img.shields.io/badge/isap-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![modern crypto](https://img.shields.io/badge/modern%20crypto-type-1f6f9f) | Lightweight side-channel-resistant AEAD |

**448 separation note:**

- `ed448`, `x448`, and `curve448` must be treated as three separate algorithm surfaces in the inventory.
- Current code may still route `curve448` through the `x448` implementation path; future agents should split metadata, tests, docs, and profile handling cleanly without merging the names back together.
### 4. PQC algorithms (41)

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![ml-kem-512](https://img.shields.io/badge/ml--kem--512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 2 | ![ml-kem-768](https://img.shields.io/badge/ml--kem--768-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 3 | ![ml-kem-1024](https://img.shields.io/badge/ml--kem--1024-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 4 | ![ml-dsa-44](https://img.shields.io/badge/ml--dsa--44-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 5 | ![ml-dsa-65](https://img.shields.io/badge/ml--dsa--65-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 6 | ![ml-dsa-87](https://img.shields.io/badge/ml--dsa--87-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 7 | ![falcon-512](https://img.shields.io/badge/falcon--512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 8 | ![falcon-1024](https://img.shields.io/badge/falcon--1024-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 9 | ![falcon-padded-512](https://img.shields.io/badge/falcon--padded--512-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 10 | ![falcon-padded-1024](https://img.shields.io/badge/falcon--padded--1024-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 11 | ![hqc-128](https://img.shields.io/badge/hqc--128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 12 | ![hqc-192](https://img.shields.io/badge/hqc--192-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 13 | ![hqc-256](https://img.shields.io/badge/hqc--256-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 14 | ![mceliece-348864](https://img.shields.io/badge/mceliece--348864-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 15 | ![mceliece-348864f](https://img.shields.io/badge/mceliece--348864f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 16 | ![mceliece-460896](https://img.shields.io/badge/mceliece--460896-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 17 | ![mceliece-460896f](https://img.shields.io/badge/mceliece--460896f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 18 | ![mceliece-6688128](https://img.shields.io/badge/mceliece--6688128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 19 | ![mceliece-6688128f](https://img.shields.io/badge/mceliece--6688128f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 20 | ![mceliece-6960119](https://img.shields.io/badge/mceliece--6960119-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 21 | ![mceliece-6960119f](https://img.shields.io/badge/mceliece--6960119f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 22 | ![mceliece-8192128](https://img.shields.io/badge/mceliece--8192128-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 23 | ![mceliece-8192128f](https://img.shields.io/badge/mceliece--8192128f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 24 | ![sphincs-sha2-128f](https://img.shields.io/badge/sphincs--sha2--128f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 25 | ![sphincs-sha2-128s](https://img.shields.io/badge/sphincs--sha2--128s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 26 | ![sphincs-sha2-192f](https://img.shields.io/badge/sphincs--sha2--192f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 27 | ![sphincs-sha2-192s](https://img.shields.io/badge/sphincs--sha2--192s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 28 | ![sphincs-sha2-256f](https://img.shields.io/badge/sphincs--sha2--256f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 29 | ![sphincs-sha2-256s](https://img.shields.io/badge/sphincs--sha2--256s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 30 | ![sphincs-shake-128f](https://img.shields.io/badge/sphincs--shake--128f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 31 | ![sphincs-shake-128s](https://img.shields.io/badge/sphincs--shake--128s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 32 | ![sphincs-shake-192f](https://img.shields.io/badge/sphincs--shake--192f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 33 | ![sphincs-shake-192s](https://img.shields.io/badge/sphincs--shake--192s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 34 | ![sphincs-shake-256f](https://img.shields.io/badge/sphincs--shake--256f-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 35 | ![sphincs-shake-256s](https://img.shields.io/badge/sphincs--shake--256s-algo-0969da) | ![current](https://img.shields.io/badge/current-surface-0969da) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | KEM / signature |
| 36 | ![bike-1](https://img.shields.io/badge/bike--1-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | BIKE level-1 code-based KEM |
| 37 | ![bike-3](https://img.shields.io/badge/bike--3-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | BIKE level-3 code-based KEM |
| 38 | ![classic-mceliece](https://img.shields.io/badge/classic--mceliece-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | Classic McEliece family alias |
| 39 | ![ntru](https://img.shields.io/badge/ntru-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | NTRU lattice-based KEM / encryption family |
| 40 | ![ntruprime](https://img.shields.io/badge/ntruprime-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | NTRU Prime lattice-based KEM family |
| 41 | ![sntrup761](https://img.shields.io/badge/sntrup761-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![post-quantum](https://img.shields.io/badge/post--quantum-type-8f3f62) | Streamlined NTRU Prime 761 KEM |

## 5. Threshold Cryptography (36)

> Threshold cryptography enables secure multi-party computation of cryptographic operations. A secret key is split into shares distributed among parties; a threshold number of shares must collaborate to perform signing or decryption.

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![frost](https://img.shields.io/badge/frost-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Schnorr Sign |
| 2 | ![tbla](https://img.shields.io/badge/tbla-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold BLS Sign |
| 3 | ![gargos](https://img.shields.io/badge/gargos-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Schnorr Sign |
| 4 | ![tecla](https://img.shields.io/badge/tecla-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | 2-party Threshold ECDSA |
| 5 | ![the-clash](https://img.shields.io/badge/the--clash-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | n-party Threshold ECDSA |
| 6 | ![classic-schnorr](https://img.shields.io/badge/classic--schnorr-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Schnorr Sign |
| 7 | ![bam](https://img.shields.io/badge/bam-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | 2-party ECDSA |
| 8 | ![ccgmp](https://img.shields.io/badge/ccgmp-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | n-party ECDSA |
| 9 | ![haystack](https://img.shields.io/badge/haystack-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold HBS |
| 10 | ![mithril](https://img.shields.io/badge/mithril-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold ML-DSA |
| 11 | ![quorus](https://img.shields.io/badge/quorus-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold ML-DSA |
| 12 | ![redeta](https://img.shields.io/badge/redeta-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold ECDLP-based Signatures |
| 13 | ![splitkey](https://img.shields.io/badge/splitkey-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Server-assisted threshold signatures and PKE |
| 14 | ![minimpc](https://img.shields.io/badge/minimpc-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold AES+SHA+MAC and gadgets |
| 15 | ![maestro](https://img.shields.io/badge/maestro-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | T-AES, T-SHA, T-MAC and gadgets |
| 16 | ![amber](https://img.shields.io/badge/amber-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Lattice-based KEM |
| 17 | ![hermine](https://img.shields.io/badge/hermine-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Sign [Lattice-based] |
| 18 | ![least](https://img.shields.io/badge/least-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Sign [code-based group-actions] |
| 19 | ![tanuki](https://img.shields.io/badge/tanuki-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold Lattice-based Signature |
| 20 | ![vinaigrette](https://img.shields.io/badge/vinaigrette-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Threshold UOV+MAYO Signatures |
| 21 | ![pantheria](https://img.shields.io/badge/pantheria-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | RLWE-based FHE and Threshold FHE |
| 22 | ![zama-tfhe](https://img.shields.io/badge/zama--tfhe-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | TFHE, Threshold FHE |
| 23 | ![zama-zhenith](https://img.shields.io/badge/zama--zhenith-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | ZKP |
| 24 | ![piver](https://img.shields.io/badge/piver-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Verifiable Secret Sharing |
| 25 | ![schmivitz](https://img.shields.io/badge/schmivitz-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | VOLEith-based ZKPoK |
| 26 | ![smallwood](https://img.shields.io/badge/smallwood-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Hash-based ZKPoK |
| 27 | ![shamir](https://img.shields.io/badge/shamir-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Shamir Secret Sharing |
| 28 | ![feldman-vss](https://img.shields.io/badge/feldman--vss-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Feldman Verifiable Secret Sharing |
| 29 | ![pedersen-vss](https://img.shields.io/badge/pedersen--vss-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Pedersen Verifiable Secret Sharing |
| 30 | ![dkg](https://img.shields.io/badge/dkg-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Distributed Key Generation |
| 31 | ![pvss](https://img.shields.io/badge/pvss-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Publicly Verifiable Secret Sharing |
| 32 | ![ot](https://img.shields.io/badge/ot-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Oblivious Transfer |
| 33 | ![vole](https://img.shields.io/badge/vole-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Vector Oblivious Linear Evaluation |
| 34 | ![beaver](https://img.shields.io/badge/beaver-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Beaver triples for MPC |
| 35 | ![mpc-ecdsa](https://img.shields.io/badge/mpc--ecdsa-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Generic MPC ECDSA signing |
| 36 | ![mpc-schnorr](https://img.shields.io/badge/mpc--schnorr-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![threshold/MPC](https://img.shields.io/badge/threshold%2FMPC-type-9a5b1f) | Generic MPC Schnorr signing |

## 6. Ascon - Lightweight Authenticated Cryptography (7)

> SP 800-232 (2024). Ascon is NIST selected lightweight crypto standard for constrained devices, covering AEAD, hashing, XOF, MAC, and PRF surfaces.

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![ascon-aead128](https://img.shields.io/badge/ascon--aead128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | authenticated encryption with associated data (128-bit key) |
| 2 | ![ascon-hash256](https://img.shields.io/badge/ascon--hash256-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | 256-bit hash output |
| 3 | ![ascon-xof128](https://img.shields.io/badge/ascon--xof128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | extendable output function (arbitrary length) |
| 4 | ![ascon-cxof128](https://img.shields.io/badge/ascon--cxof128-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | customizable XOF (domain-separated variant of xof128) |
| 5 | ![ascon-mac](https://img.shields.io/badge/ascon--mac-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | Ascon message authentication code |
| 6 | ![ascon-prf](https://img.shields.io/badge/ascon--prf-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | Ascon pseudorandom function |
| 7 | ![ascon-80pq](https://img.shields.io/badge/ascon--80pq-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![lightweight crypto](https://img.shields.io/badge/lightweight%20crypto-type-2f6f9f) | historical Ascon AEAD variant with 80-bit post-quantum security target |

## 7. DRBG / Randomness Infrastructure (7)

> SP 800-90A style deterministic random bit generators and supporting randomness infrastructure.

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![ctr-drbg](https://img.shields.io/badge/ctr--drbg-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | AES-256-CTR based DRBG (most common in hardware/HSM contexts) |
| 2 | ![hash-drbg](https://img.shields.io/badge/hash--drbg-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | SHA-based DRBG |
| 3 | ![hmac-drbg](https://img.shields.io/badge/hmac--drbg-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | HMAC-based DRBG (default in many TLS stacks) |
| 4 | ![csprng-system](https://img.shields.io/badge/csprng--system-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | OS-backed cryptographically secure RNG abstraction |
| 5 | ![trng](https://img.shields.io/badge/trng-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | Hardware true-random entropy source abstraction |
| 6 | ![entropy-pool](https://img.shields.io/badge/entropy--pool-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | Entropy accumulation and conditioning |
| 7 | ![reseed-scheduler](https://img.shields.io/badge/reseed--scheduler-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![randomness/DRBG](https://img.shields.io/badge/randomness%2FDRBG-type-856404) | DRBG reseed policy / scheduling |

## 8. Stateful Hash-Based Signatures (2)

> SP 800-208 / RFC 8391 stateful hash-based signature schemes. Reusing signing state is catastrophic.

| # | Algorithm | Status | Type | Note |
| ---: | --- | --- | --- | --- |
| 1 | ![lms](https://img.shields.io/badge/lms-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![stateful signature](https://img.shields.io/badge/stateful%20signature-type-4b5563) | Leighton-Micali Signatures (SP 800-208); NIST approved |
| 2 | ![xmss](https://img.shields.io/badge/xmss-algo-2da44e) | ![planned](https://img.shields.io/badge/planned-surface-2da44e) | ![stateful signature](https://img.shields.io/badge/stateful%20signature-type-4b5563) | eXtended Merkle Signature Scheme (RFC 8391); NIST approved |

## Inventory totals

| Group | Count |
| --- | ---: |
| Encoding | 14 |
| Hash / KDF-hash | 59 |
| Modern | 84 |
| PQC | 41 |
| Threshold | 36 |
| Ascon | 7 |
| DRBG / randomness | 7 |
| Stateful hash-based signatures | 2 |
| **Total** | **250** |

## Inventory note

Green `planned` badges mark algorithm surfaces that are intended to be added or exposed. The marker does not mean the implementation already exists in the tree.
