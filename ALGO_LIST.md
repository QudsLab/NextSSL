# Algorithm List

All algorithms/implementations that exist as source in `src/`. Short reference only — see `ALGORITHM.md` for full API details.

Scan method: exhaustive directory walk of every sub-folder under `src/`, confirmed against matching header/source files.

---

## 1. Hash — Fast (`src/primitives/hash/fast/`)

| Algorithm | Notes                                           |
| --------- | ----------------------------------------------- |
| SHA-224   | Truncated SHA-256                               |
| SHA-256   | Streaming init/update/final                     |
| SHA-384   | Truncated SHA-512 (exposed via `hash_legacy.h`) |
| SHA-512   |                                                 |
| BLAKE2b   | 1–64 byte output, optional key                  |
| BLAKE2s   | 1–32 byte output, optional key                  |
| BLAKE3    | XOF, optional key, SIMD dispatch                |

## 2. Hash — Sponge / XOF (`src/primitives/hash/sponge_xof/`)

Adapter files confirmed: `keccak_256.c`, `sha3_224.c`, `sha3_256.c` (sha3 dir), `sha3_384.c`, `sha3_512.c`, `shake128.c`, `shake256.c`.

| Algorithm  | Notes                                                                        |
| ---------- | ---------------------------------------------------------------------------- |
| SHA3-224   |                                                                              |
| SHA3-256   |                                                                              |
| SHA3-384   |                                                                              |
| SHA3-512   |                                                                              |
| Keccak-256 | Raw Keccak (non-NIST padding) — only the 256-bit variant has its own adapter |
| SHAKE-128  | XOF, arbitrary output length                                                 |
| SHAKE-256  | XOF, arbitrary output length                                                 |

> **Correction vs. previous version:** Keccak-224 / Keccak-384 / Keccak-512 adapter files do **not** exist in `sponge_xof/`; only Keccak-256 (raw) is present.

## 3. Hash — Memory-Hard (`src/primitives/hash/memory_hard/`)

| Algorithm | Notes                                               |
| --------- | --------------------------------------------------- |
| Argon2id  | Recommended — hybrid (GPU + side-channel resistant) |
| Argon2i   | Side-channel resistant                              |
| Argon2d   | Max GPU resistance                                  |

---

## 4. Legacy — Alive (`src/legacy/alive/`)

Weakened but still encountered in real systems.

| Algorithm  | Notes                                         |
| ---------- | --------------------------------------------- |
| SHA-1      | Collision attacks practical (SHAttered, 2017) |
| MD5        | Completely broken; trivial collisions         |
| RIPEMD-160 | Still used (Bitcoin addresses)                |
| Whirlpool  |                                               |
| NT Hash    | Windows NTLM (MD4-based)                      |
| AES-ECB    | Bare block, no IV                             |

## 5. Legacy — Unsafe (`src/legacy/unsafe/`)

Cryptographically broken — backward compatibility only.

| Algorithm  |
| ---------- |
| MD2        |
| MD4        |
| SHA-0      |
| HAS-160    |
| RIPEMD-128 |
| RIPEMD-256 |
| RIPEMD-320 |

---

## 6. Symmetric Cipher Modes (`src/primitives/cipher/`)

All AES-based.

| Mode    | Notes                                                     |
| ------- | --------------------------------------------------------- |
| AES-CBC |                                                           |
| AES-CFB |                                                           |
| AES-CTR |                                                           |
| AES-OFB |                                                           |
| AES-XTS | Double key                                                |
| AES-KW  | Key wrap (RFC 3394)                                       |
| AES-FPE | FF1 / FF3-1 format-preserving encryption                  |
| AES-ECB | Via `legacy/alive/aes_ecb` + `primitives/cipher/aes_core` |

## 7. AEAD (`src/primitives/aead/`)

| Algorithm         | Notes                                                                         |
| ----------------- | ----------------------------------------------------------------------------- |
| AES-GCM           | NIST standard                                                                 |
| AES-GCM-SIV       | Nonce-misuse resistant                                                        |
| AES-CCM           | Counter + CBC-MAC                                                             |
| AES-EAX           |                                                                               |
| AES-OCB           |                                                                               |
| AES-SIV           |                                                                               |
| AES-Poly1305      |                                                                               |
| ChaCha20-Poly1305 | 12-byte nonce, Monocypher backend; optional Monocypher-Ed25519 in `optional/` |

## 8. Legacy Ciphers (`src/interfaces/base/cipher_legacy.h`)

Exposed only for compatibility. These are **not** in `primitives/cipher/` as distinct source modules but are wired up via the `cipher_legacy` interface.

| Algorithm     | Notes                                        |
| ------------- | -------------------------------------------- |
| AES-256-CBC   | Deprecated; no authentication                |
| AES-256-CTR   | Deprecated; no authentication                |
| 3DES-EDE3-CBC | Broken (Sweet32 attack); ancient legacy only |

---

## 9. MAC (`src/primitives/mac/` + `src/PQCrypto/common/hkdf/` + `src/interfaces/base/mac.h`)

| Algorithm     | Source                                                  | Notes                               |
| ------------- | ------------------------------------------------------- | ----------------------------------- |
| AES-CMAC      | `primitives/mac/aes_cmac/`                              |                                     |
| SipHash       | `primitives/mac/siphash/`                               | 8 or 16 byte output                 |
| HMAC-SHA256   | `pqc_hmac_sha256` in `common/hkdf/hkdf.h`; `base/mac.h` |                                     |
| HMAC-SHA512   | `base/mac.h`                                            | **Was missing in previous version** |
| HMAC-SHA3-256 | `hmac_sha3_256` in `common/hkdf/hkdf.h`; `base/mac.h`   |                                     |
| HMAC-SHA3-512 | `hmac_sha3_512` in `common/hkdf/hkdf.h`                 |                                     |

---

## 10. ECC — Primitive (`src/primitives/ecc/`)

Source implementations of underlying ECC curves.

| Algorithm        | Notes                                  |
| ---------------- | -------------------------------------- |
| Ed25519 + X25519 | EdDSA sign/verify; X25519 key exchange |
| Curve448 + X448  | ECDH, 56-byte key                      |
| Ed448            | EdDSA + Ed448ph (pre-hash)             |
| Ristretto255     | Prime-order group over Ed25519         |
| Elligator2       | Hash-to-curve encoding/decoding        |

## 11. ECC — Interface (`src/interfaces/base/ecc.h`)

**⚠️ NOTE: This section documents PLANNED APIs that do NOT exist yet.**

> **Status Update (Mar 2026):** The `src/interfaces/base/` directory does not exist. No NIST curve implementations (P-256/P-384/P-521) are present in the codebase. These entries document API contracts planned for future implementation.

| Curve               | Status          | Notes                                 |
| ------------------- | --------------- | ------------------------------------- |
| Curve25519 (X25519) | ✅ Implemented  | Scalar mult + public key gen          |
| Curve448            | ✅ Implemented  | Scalar mult                           |
| NIST P-256          | ❌ Not Impl     | Point mul, base mul, point validation |
| NIST P-384          | ❌ Not Impl     | Base mul, point validation            |
| NIST P-521          | ❌ Not Impl     | Base mul, point validation            |

---

## 12. Digital Signatures (`src/interfaces/base/sign.h`)

**⚠️ NOTE: ECDSA P-256 is NOT implemented — interface-only.**

> **Status Update (Mar 2026):** Only Ed25519 and ML-DSA-65 have implementations. ECDSA P-256 is a planned API contract with no backing source code.

| Algorithm   | Status         | Notes                              |
| ----------- | -------------- | ---------------------------------- |
| Ed25519     | ✅ Implemented | Keypair, sign, verify (RFC 8032)   |
| ECDSA P-256 | ❌ Not Impl    | Keypair, sign, verify (FIPS 186-4) |
| ML-DSA-65   | ✅ Implemented | Post-quantum (NIST FIPS 204, L3)   |

---

## 13. Key Derivation Functions

### `src/PQCrypto/common/hkdf/hkdf.h` + `src/interfaces/base/kdf.h`

> **HKDF-SHA512 and PBKDF2-HMAC-SHA256 were missing in previous version.**

| Algorithm           | Source             | Notes                               |
| ------------------- | ------------------ | ----------------------------------- |
| HKDF-SHA256         | `hkdf.h` + `kdf.h` | Extract, expand, one-shot; RFC 5869 |
| HKDF-SHA512         | `kdf.h`            | **Was missing**                     |
| HKDF-SHA3-256       | `hkdf.h`           | Extract, expand, one-shot           |
| HKDF-SHA3-512       | `hkdf.h`           | Extract, expand, one-shot           |
| HKDF-Expand-Label   | `hkdf.h`           | RFC 8446 TLS 1.3 style (SHA256)     |
| KDF-SHAKE256        | `hkdf.h`           | XOF-based, arbitrary output         |
| PBKDF2-HMAC-SHA256  | `kdf.h`            | Legacy; RFC 8018; **Was missing**   |
| Argon2id (KDF mode) | `kdf.h`            | Password-based, memory-hard         |

---

## 14. DRBG (`src/utils/drbg/` + `src/PQCrypto/common/drbg/`)

| Implementation     | Notes                                                           |
| ------------------ | --------------------------------------------------------------- |
| CTR_DRBG (AES-256) | `utils/drbg/` — init / reseed / generate / free                 |
| PQC DRBG           | `PQCrypto/common/drbg/` — AES-256-CTR, seeded via `randombytes` |

---

## 15. Encoding (`src/utils/encoding/`)

| Encoding  | Notes                                     |
| --------- | ----------------------------------------- |
| Base64    | Standard (RFC 4648); encode/decode        |
| Base64URL | URL-safe variant; encode/decode           |
| Hex       | Lowercase hex; encode/decode              |
| FF70      | Custom framed format with BLAKE3 checksum |

## 16. Radix (`src/utils/radix/`)

> **Base16, Base32, Base58 were completely missing in previous version.** These are in a separate `radix/` module distinct from `encoding/`.

| Encoding  | Notes                                    |
| --------- | ---------------------------------------- |
| Base16    | Hex encoding (lower-level, radix module) |
| Base32    | RFC 4648                                 |
| Base58    | Bitcoin-style alphabet                   |
| Base64    | Standard (radix module copy)             |
| Base64URL | URL-safe (radix module copy)             |

---

## 17. Post-Quantum Cryptography (`src/PQCrypto/`)

### KEM (`crypto_kem/`) — 16 variants

| Algorithm                   | Security     |
| --------------------------- | ------------ |
| ML-KEM-512                  | L1           |
| ML-KEM-768                  | L3           |
| ML-KEM-1024                 | L5           |
| HQC-128                     | L1           |
| HQC-192                     | L3           |
| HQC-256                     | L5           |
| McEliece-348864 / 348864f   | L1 / L1 fast |
| McEliece-460896 / 460896f   | L3 / L3 fast |
| McEliece-6688128 / 6688128f | L5 / L5 fast |
| McEliece-6960119 / 6960119f | L5 / L5 fast |
| McEliece-8192128 / 8192128f | L5 / L5 fast |

### Signature (`crypto_sign/`) — 19 variants

| Algorithm                                | Security           |
| ---------------------------------------- | ------------------ |
| ML-DSA-44                                | L2                 |
| ML-DSA-65                                | L3                 |
| ML-DSA-87                                | L5                 |
| Falcon-512                               | L1, compact sig    |
| Falcon-1024                              | L5, compact sig    |
| Falcon-Padded-512                        | L1, fixed-size sig |
| Falcon-Padded-1024                       | L5, fixed-size sig |
| SPHINCS+-SHA2-128f-simple / 128s-simple  | L1 fast / small    |
| SPHINCS+-SHA2-192f-simple / 192s-simple  | L3 fast / small    |
| SPHINCS+-SHA2-256f-simple / 256s-simple  | L5 fast / small    |
| SPHINCS+-SHAKE-128f-simple / 128s-simple | L1 fast / small    |
| SPHINCS+-SHAKE-192f-simple / 192s-simple | L3 fast / small    |
| SPHINCS+-SHAKE-256f-simple / 256s-simple | L5 fast / small    |

### PQC Common (`common/`)

| Primitive                     | Notes                                              |
| ----------------------------- | -------------------------------------------------- |
| HKDF (SHA256 + SHA3 variants) | `common/hkdf/hkdf.c` — used internally by KEM/Sign |
| DRBG (AES-256-CTR)            | `common/drbg/drbg.c` — seeded via `randombytes`    |
| Keccak-2x                     | Optimized permutation                              |
| Keccak-4x                     | AVX2 permutation                                   |
| SHA-2 (sha2.c)                | Used internally by PQC algorithms                  |
| AES core (aes.c)              | Used internally by PQC algorithms                  |
| FIPS 202 (fips202.c)          | Keccak-based XOF / SHA-3                           |

---

## 18. Proof of Work (`src/utils/pow/`)

PoW uses existing primitive hash algorithms as backends. Enum IDs from `pow_hash_types.h`:

| Algorithm                             | Category              |
| ------------------------------------- | --------------------- |
| BLAKE3                                | primitive_fast        |
| SHA-256                               | primitive_fast        |
| SHA3-256                              | primitive_sponge_xof  |
| Argon2id                              | primitive_memory_hard |
| MD5 _(legacy, disabled by default)_   | legacy_alive          |
| SHA-1 _(legacy, disabled by default)_ | legacy_alive          |

PoW server/client role separation: `server/` generates challenges; `client/` solves them.

---

## Count Summary

| Category                         | Count                                                              |
| -------------------------------- | ------------------------------------------------------------------ |
| Fast Hashes (primitives)         | 7 (SHA-224/256/384/512, BLAKE2b/2s/3)                              |
| Sponge/XOF Hashes                | 7 (SHA3 ×4, Keccak-256, SHAKE ×2)                                  |
| Memory-Hard Hashes               | 3 (Argon2id/i/d)                                                   |
| Legacy Alive                     | 6                                                                  |
| Legacy Unsafe                    | 7                                                                  |
| AES Cipher Modes (primitives)    | 7 (CBC, CFB, CTR, OFB, XTS, KW, FPE) + ECB via legacy              |
| Legacy Ciphers (interface layer) | 3 (AES-CBC, AES-CTR, 3DES)                                         |
| AEAD                             | 8 (7 AES + ChaCha20-Poly1305)                                      |
| MAC                              | 6 (CMAC, SipHash, HMAC-SHA256/512, HMAC-SHA3-256/512)              |
| ECC (primitives)                 | 5 (Ed25519+X25519, Curve448+X448, Ed448, Ristretto255, Elligator2) |
| ECC (interface layer curves)     | 5 (Curve25519, Curve448, P-256, P-384, P-521)                      |
| Signatures (interface)           | 3 (Ed25519, ECDSA-P256, ML-DSA-65)                                 |
| KDF                              | 8 (HKDF×6, PBKDF2, Argon2id-KDF)                                   |
| DRBG                             | 2                                                                  |
| Encoding                         | 4 (Base64, Base64URL, Hex, FF70)                                   |
| Radix                            | 5 (Base16, Base32, Base58, Base64, Base64URL)                      |
| PQC KEM                          | 16                                                                 |
| PQC Signature                    | 19                                                                 |
| PQC Common Primitives            | 7                                                                  |
| PoW Algorithms (backends)        | 6                                                                  |
| **Total distinct**               | **~128**                                                           |
