# NextSSL — Complete Source Directory Map

> **Auto-generated reference** — Every directory and file inside `src/` is listed with its purpose.
> Designed so any AI agent can navigate the codebase without scanning the filesystem.

---

## Table of Contents

1. [Top-Level Layout](#1-top-level-layout)
2. [src/include/](#2-srcinclude)
3. [src/primitives/](#3-srcprimitives)
   - 3.1 [primitives/hash/](#31-primitiveshash)
   - 3.2 [primitives/cipher/](#32-primitivescipher)
   - 3.3 [primitives/aead/](#33-primitivesaead)
   - 3.4 [primitives/mac/](#34-primitivesmac)
   - 3.5 [primitives/ecc/](#35-primitivesecc)
4. [src/legacy/](#4-srclegacy)
   - 4.1 [legacy/alive/](#41-legacyalive)
   - 4.2 [legacy/unsafe/](#42-legacyunsafe)
5. [src/utils/](#5-srcutils)
   - 5.1 [utils/hash/](#51-utilshash)
   - 5.2 [utils/drbg/](#52-utilsdrbg)
   - 5.3 [utils/encoding/](#53-utilsencoding)
   - 5.4 [utils/pow/](#54-utilspow)
   - 5.5 [utils/pqc/](#55-utilspqc)
   - 5.6 [utils/ root files](#56-utils-root-files)
6. [src/PQCrypto/](#6-srcpqcrypto)
   - 6.1 [PQCrypto/common/](#61-pqcryptocommon)
   - 6.2 [PQCrypto/crypto_kem/](#62-pqcryptocrypto_kem)
   - 6.3 [PQCrypto/crypto_sign/](#63-pqcryptocrypto_sign)

---

## 1. Top-Level Layout

```
src/
├── include/          # Unified public headers
├── primitives/       # Core cryptographic primitive implementations
│   ├── hash/         #   Hash algorithms (fast, sponge, memory-hard)
│   ├── cipher/       #   AES block cipher modes
│   ├── aead/         #   Authenticated encryption modes
│   ├── mac/          #   Message authentication codes
│   └── ecc/          #   Elliptic curve cryptography
├── legacy/           # Legacy/deprecated algorithm implementations
│   ├── alive/        #   Weak but still used (MD5, SHA-1, etc.)
│   └── unsafe/       #   Cryptographically broken (MD2, MD4, SHA-0, etc.)
├── utils/            # Wrapper APIs, utilities, and protocol code
│   ├── hash/         #   Leyline hash dispatcher wrappers
│   ├── drbg/         #   Deterministic random bit generator
│   ├── encoding/     #   Base64, Hex, FF70 encoding
│   ├── pow/          #   Proof-of-Work client/server protocol
│   └── pqc/          #   PQC interface headers
└── PQCrypto/         # Post-quantum cryptographic implementations (PQClean)
    ├── common/       #   Shared PQC support (SHA2, FIPS202, HKDF, DRBG, RNG)
    ├── crypto_kem/   #   Key Encapsulation Mechanism implementations
    └── crypto_sign/  #   Digital Signature implementations
```

**Total file count:** ~2,948 files across the tree.

---

## 2. `src/include/`

| File            | Purpose                                                                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crypto_core.h` | **Unified entry-point header.** Includes the recommended default primitives: BLAKE3, SHA-256, SHA3, AES-GCM, ChaCha20-Poly1305, Ed25519, Curve448, and the PoW protocol. |

---

## 3. `src/primitives/`

### 3.1 `primitives/hash/`

#### `hash/fast/` — High-Speed Hash Functions

| Directory  | Files                                                                                                                                                    | Algorithm                                |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `blake2b/` | `blake2b.c`, `blake2b.h`                                                                                                                                 | BLAKE2b (1–64 byte output, optional key) |
| `blake2s/` | `blake2s.c`, `blake2s.h`                                                                                                                                 | BLAKE2s (1–32 byte output, optional key) |
| `blake3/`  | `blake3.c`, `blake3.h`, `blake3_impl.h`, `blake3_dispatch.c`, `blake3_portable.c`, `blake3_sse2.c`, `blake3_sse41.c`, `blake3_avx2.c`, `blake3_avx512.c` | BLAKE3 (XOF, SIMD-accelerated, v1.8.3)   |
| `sha224/`  | `sha224.c`, `sha224.h`                                                                                                                                   | SHA-224                                  |
| `sha256/`  | `sha256.c`, `sha256.h`                                                                                                                                   | SHA-256 (+ PoW midstate optimisations)   |
| `sha512/`  | `sha512.c`, `sha512.h`                                                                                                                                   | SHA-512 and SHA-384                      |

#### `hash/sponge_xof/` — Sponge-Based and Extendable-Output Functions

| Directory   | Files                      | Algorithm                          |
| ----------- | -------------------------- | ---------------------------------- |
| `sha3/`     | `sha3.c`, `sha3.h`         | SHA3-256, SHA3-512, Keccak-256     |
| `sha3_224/` | `sha3_224.c`, `sha3_224.h` | SHA3-224                           |
| `sha3_384/` | `sha3_384.c`, `sha3_384.h` | SHA3-384                           |
| `keccak/`   | `keccak.c`, `keccak.h`     | Keccak-224, Keccak-384, Keccak-512 |
| `shake/`    | `shake.c`, `shake.h`       | SHAKE-128, SHAKE-256 (XOF)         |

#### `hash/memory_hard/` — Password Hashing / Key Stretching

| Directory   | Files                                                                                                            | Algorithm                               |
| ----------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `Argon2id/` | `argon2id.c`, `argon2id.h`                                                                                       | Argon2id (recommended variant)          |
| `Argon2i/`  | `argon2i.c`, `argon2i.h`                                                                                         | Argon2i (data-independent)              |
| `Argon2d/`  | `argon2d.c`, `argon2d.h`                                                                                         | Argon2d (data-dependent, fastest)       |
| `blake2/`   | `blake2b.c`, `blake2.h`, `blake2-impl.h`, `blamka-round-ref.h`, `blamka-round-opt.h`                             | BLAKE2b (internal mixing for Argon2)    |
| `utils/`    | `argon2.c`, `argon2.h`, `core.c`, `core.h`, `encoding.c`, `encoding.h`, `ref.c`, `opt.c`, `thread.c`, `thread.h` | Argon2 core engine, encoding, threading |

---

### 3.2 `primitives/cipher/` — AES Block Cipher Modes

| Directory   | Files                                           | Mode                                                       |
| ----------- | ----------------------------------------------- | ---------------------------------------------------------- |
| `aes_core/` | `aes_core.c`, `aes_common.h`, `aes_internal.h`  | AES engine (Rijndael), GF(2^128), key expansion, constants |
| `aes_cbc/`  | `aes_cbc.c`, `aes_cbc.h`                        | AES-CBC (Cipher Block Chaining)                            |
| `aes_cfb/`  | `aes_cfb.c`, `aes_cfb.h`                        | AES-CFB (Cipher Feedback)                                  |
| `aes_ofb/`  | `aes_ofb.c`, `aes_ofb.h`                        | AES-OFB (Output Feedback)                                  |
| `aes_ctr/`  | `aes_ctr.c`, `aes_ctr.h`                        | AES-CTR (Counter Mode) + internal modes for GCM/CCM/SIV    |
| `aes_xts/`  | `aes_xts.c`, `aes_xts.h`                        | AES-XTS (Disk encryption)                                  |
| `aes_kw/`   | `aes_kw.c`, `aes_kw.h`                          | AES Key Wrap (RFC 3394)                                    |
| `aes_fpe/`  | `aes_fpe.c`, `aes_fpe.h`, `aes_fpe_alphabets.h` | AES Format-Preserving Encryption (FF1/FF3-1)               |

---

### 3.3 `primitives/aead/` — Authenticated Encryption with Associated Data

| Directory                     | Files                                                                        | Mode                                           |
| ----------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------- |
| `aes_gcm/`                    | `aes_gcm.c`, `aes_gcm.h`                                                     | AES-GCM (Galois/Counter Mode)                  |
| `aes_ccm/`                    | `aes_ccm.c`, `aes_ccm.h`                                                     | AES-CCM (Counter with CBC-MAC)                 |
| `aes_ocb/`                    | `aes_ocb.c`, `aes_ocb.h`                                                     | AES-OCB (Offset Codebook)                      |
| `aes_eax/`                    | `aes_eax.c`, `aes_eax.h`                                                     | AES-EAX                                        |
| `aes_siv/`                    | `aes_siv.c`, `aes_siv.h`                                                     | AES-SIV (Synthetic IV, nonce-misuse resistant) |
| `aes_gcm_siv/`                | `aes_gcm_siv.c`, `aes_gcm_siv.h`                                             | AES-GCM-SIV (nonce-misuse resistant)           |
| `aes_poly1305/`               | `aes_poly1305.c`, `aes_poly1305.h`                                           | AES-Poly1305 MAC                               |
| `chacha20_poly1305/`          | `chacha20_poly1305.c`, `chacha20_poly1305.h`, `monocypher.c`, `monocypher.h` | ChaCha20-Poly1305 AEAD (Monocypher backend)    |
| `chacha20_poly1305/optional/` | `monocypher-ed25519.c`, `monocypher-ed25519.h`                               | Optional Monocypher Ed25519                    |

---

### 3.4 `primitives/mac/` — Message Authentication Codes

| Directory   | Files                      | Algorithm                              |
| ----------- | -------------------------- | -------------------------------------- |
| `aes_cmac/` | `aes_cmac.c`, `aes_cmac.h` | AES-CMAC (NIST SP 800-38B)             |
| `siphash/`  | `siphash.c`, `siphash.h`   | SipHash-2-4 (64-bit or 128-bit output) |

---

### 3.5 `primitives/ecc/` — Elliptic Curve Cryptography

#### `ecc/ed25519/` — Ed25519 Signatures + X25519 Key Exchange

| File                    | Purpose                                                      |
| ----------------------- | ------------------------------------------------------------ |
| `ed25519.h`             | Public API (keypair, sign, verify, key_exchange, add_scalar) |
| `keypair.c`             | Key pair generation from 32-byte seed                        |
| `sign.c`                | EdDSA signing                                                |
| `verify.c`              | EdDSA verification                                           |
| `key_exchange.c`        | X25519 Diffie-Hellman                                        |
| `add_scalar.c`          | Scalar addition to keys                                      |
| `seed.c`                | Secure seed generation                                       |
| `fe.c` / `fe.h`         | Field element arithmetic (Curve25519)                        |
| `ge.c` / `ge.h`         | Group element operations                                     |
| `sc.c` / `sc.h`         | Scalar arithmetic                                            |
| `sha512.c` / `sha512.h` | Embedded SHA-512 for Ed25519 internals                       |
| `fixedint.h`            | Fixed-width integer types                                    |
| `precomp_data.h`        | Precomputed group elements (~99 KB)                          |

#### `ecc/curve448/` — Curve448 ECDH + Ed448 Signatures

| File                                | Purpose                                                         |
| ----------------------------------- | --------------------------------------------------------------- |
| `curve448.c` / `curve448.h`         | X448 key agreement (56-byte keys)                               |
| `curve448_det.c` / `curve448_det.h` | Deterministic key generation from seed                          |
| `ed448.c` / `ed448.h`               | Ed448 signatures (57-byte keys, 114-byte sigs, context support) |
| `fe_448.c` / `fe_448.h`             | Field element arithmetic (Goldilocks)                           |
| `ge_448.c` / `ge_448.h`             | Group element operations (~547 KB precomputed)                  |
| `wolf_shim.h`                       | wolfSSL compatibility shim (type definitions)                   |

#### `ecc/elligator2/` — Elligator2 Point Encoding

| File                            | Purpose                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------ |
| `elligator2.c` / `elligator2.h` | Map hidden→curve, reverse map, key pair generation. Censorship-resistant key hiding. |

#### `ecc/ristretto255/` — Ristretto255 Group Abstraction

| File                                | Purpose                                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `ristretto255.c` / `ristretto255.h` | Point validation, addition, subtraction, hash-to-point. Prime-order group over Curve25519. |

---

## 4. `src/legacy/`

### 4.1 `legacy/alive/` — Weak but Still Encountered

| Directory    | Files                        | Algorithm                                               | Status                                    |
| ------------ | ---------------------------- | ------------------------------------------------------- | ----------------------------------------- |
| `md5/`       | `md5.c`, `md5.h`             | MD5 (128-bit)                                           | Collision-broken, still used in checksums |
| `sha1/`      | `sha1.c`, `sha1.h`           | SHA-1 (160-bit)                                         | Collision-broken, legacy TLS/Git          |
| `ripemd160/` | `ripemd160.c`, `ripemd160.h` | RIPEMD-160 (160-bit)                                    | Bitcoin address hashing                   |
| `whirlpool/` | `whirlpool.c`, `whirlpool.h` | Whirlpool (512-bit) + Whirlpool-0, Whirlpool-T variants | ISO standard                              |
| `nt_hash/`   | `nt.c`, `nt.h`               | NT Hash / NTLM (128-bit)                                | Windows password hashing                  |
| `aes_ecb/`   | `aes_ecb.c`, `aes_ecb.h`     | AES-ECB                                                 | No IV, pattern-leaking, legacy only       |

### 4.2 `legacy/unsafe/` — Cryptographically Broken

| Directory    | Files                        | Algorithm                   | Digest |
| ------------ | ---------------------------- | --------------------------- | ------ |
| `md2/`       | `md2.c`, `md2.h`             | MD2                         | 16 B   |
| `md4/`       | `md4.c`, `md4.h`             | MD4                         | 16 B   |
| `sha0/`      | `sha0.c`, `sha0.h`           | SHA-0 (original, pre-SHA-1) | 20 B   |
| `has160/`    | `has160.c`, `has160.h`       | HAS-160 (Korean standard)   | 20 B   |
| `ripemd128/` | `ripemd128.c`, `ripemd128.h` | RIPEMD-128                  | 16 B   |
| `ripemd256/` | `ripemd256.c`, `ripemd256.h` | RIPEMD-256                  | 32 B   |
| `ripemd320/` | `ripemd320.c`, `ripemd320.h` | RIPEMD-320                  | 40 B   |

---

## 5. `src/utils/`

### 5.1 `utils/hash/` — Leyline Hash Wrapper Layer

Provides the unified `leyline_*` API that backends call into the primitives.

| File                             | Purpose                                                                                                                                 |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `primitive_fast.c` / `.h`        | Wrappers: `leyline_sha256`, `leyline_sha512`, `leyline_blake3`, `leyline_blake2b`, `leyline_blake2s`                                    |
| `primitive_memory_hard.c` / `.h` | Wrappers: `leyline_argon2id`, `leyline_argon2i`, `leyline_argon2d` (+ `LeylineArgon2Params` struct)                                     |
| `primitive_sponge_xof.c` / `.h`  | Wrappers: `leyline_sha3_256`, `leyline_sha3_512`, `leyline_keccak_256`, `leyline_shake128`, `leyline_shake256`                          |
| `legacy_alive.c` / `.h`          | Wrappers: `leyline_md5`, `leyline_sha1`                                                                                                 |
| `legacy_unsafe.c` / `.h`         | Wrappers: `leyline_md2`, `leyline_md4`, `leyline_sha0`, `leyline_ripemd128`, `leyline_ripemd256`, `leyline_ripemd320`, `leyline_has160` |

### 5.2 `utils/drbg/` — DRBG Utility

| File                | Purpose                                                                                       |
| ------------------- | --------------------------------------------------------------------------------------------- |
| `drbg.c` / `drbg.h` | CTR_DRBG (AES-256). `ctr_drbg_init`, `ctr_drbg_reseed`, `ctr_drbg_generate`, `ctr_drbg_free`. |

### 5.3 `utils/encoding/` — Data Encoding

| File                          | Purpose                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------- |
| `base64.c` / `base64.h`       | Standard Base64 encode/decode                                                     |
| `base64url.c` / `base64url.h` | URL-safe Base64 (no padding) encode/decode                                        |
| `hex.c` / `hex.h`             | Hexadecimal encode/decode                                                         |
| `ff70.c` / `ff70.h`           | FlexFrame-70 custom encoding (header, config, payload, BLAKE3 checksum, metadata) |

### 5.4 `utils/pow/` — Proof-of-Work Protocol

```
pow/
├── client/
│   ├── safety.c                         # Safety checks (resource limits)
│   ├── solver.c                         # PoW nonce solver engine
│   ├── interfaces/
│   │   ├── pow_client.h                 # Client API (solve, check_safety)
│   │   └── pow_protocol.h              # Protocol types (PoWChallenge, PoWAlgorithm, PoWError)
│   └── core/
│       ├── challenge_suite.c            # Challenge dispatch to hash backends
│       ├── pow_dispatch.h               # Dispatch macros
│       ├── pow_hash_types.h             # PoWHashArgs, Argon2Ctx, PoW_HashFunc typedef
│       ├── pow_primitives.h             # Aggregate include for all hash dispatchers
│       ├── pow_primitive_fast.c / .h    # SHA-256, BLAKE3 dispatch for PoW
│       ├── pow_primitive_memory_hard.c / .h  # Argon2id dispatch for PoW
│       ├── pow_primitive_sponge_xof.c / .h   # SHA3-256 dispatch for PoW
│       ├── pow_legacy_alive.c / .h      # MD5, SHA-1 dispatch for PoW
│       ├── pow_legacy_unsafe.c / .h     # Unsafe hash dispatch for PoW
│       └── pow_protocol.c              # Protocol serialization helpers
└── server/
    ├── generator.c                      # Challenge generation
    ├── verifier.c                       # Solution verification
    ├── interfaces/
    │   ├── pow_server.h                 # Server API (init, add_input, verify, tune)
    │   └── pow_protocol.h              # Shared protocol header (same as client)
    ├── complexity/
    │   ├── calc_interface.h             # Complexity calculator interface
    │   ├── calc_sha.c                   # SHA/BLAKE complexity estimation
    │   ├── calc_blake.c                 # BLAKE complexity estimation
    │   └── calc_argon2.c               # Argon2 complexity estimation
    └── core/
        # Same dispatch files as client (challenge_suite, pow_primitive_*, etc.)
```

### 5.5 `utils/pqc/` — PQC Interface Headers

| File               | Purpose                                                                       |
| ------------------ | ----------------------------------------------------------------------------- |
| `interface_kem.h`  | Leyline KEM wrapper declarations (ML-KEM-512/768/1024)                        |
| `interface_sign.h` | Leyline signature wrapper declarations (ML-DSA-44/65/87, SPHINCS+-SHAKE-128f) |

### 5.6 `utils/` Root Files

| File                          | Purpose                                                                                                                                                                             |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pqc_main.c`                  | **Master PQC wrapper** (925 lines). Wraps all 35 PQC algorithm variants with standard + deterministic modes. Includes DRBG seeding via HKDF and UDBF (User Determined Byte Feeder). |
| `base_encryption.c`           | AES mode aggregator — includes all cipher/AEAD headers and provides `base_encryption_info()`.                                                                                       |
| `ahs_argon.c` / `ahs_argon.h` | Advanced Hash Exporter for Argon2 — `ahs_argon_info()`.                                                                                                                             |

---

## 6. `src/PQCrypto/`

### 6.1 `PQCrypto/common/` — Shared PQC Support Library

| File / Dir                                  | Purpose                                                                                               |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `aes.c` / `aes.h`                           | AES for internal PQC use (key schedule, ECB)                                                          |
| `fips202.c` / `fips202.h`                   | FIPS 202: SHA3-256/384/512, SHAKE-128/256 (incremental + one-shot)                                    |
| `sha2.c` / `sha2.h`                         | SHA-224/256/384/512 for PQC internal use (namespaced `pqc_sha*`)                                      |
| `sp800-185.c` / `sp800-185.h`               | NIST SP 800-185: cSHAKE                                                                               |
| `nistseedexpander.c` / `nistseedexpander.h` | NIST AES-CTR seed expander                                                                            |
| `randombytes.c` / `randombytes.h`           | Platform RNG + CTR-DRBG override with seed/reseed/UDBF                                                |
| `compat.h`                                  | Cross-platform compatibility macros                                                                   |
| `crypto_declassify.h`                       | Constant-time declassification                                                                        |
| `hkdf/hkdf.c` / `hkdf.h`                    | HKDF-SHA256, HKDF-SHA3-256, HKDF-SHA3-512, HKDF-Expand-Label, KDF-SHAKE256, HMAC-SHA256, HMAC-SHA3-\* |
| `drbg/drbg.c` / `drbg.h`                    | AES-256-CTR DRBG for PQClean                                                                          |
| `keccak2x/`                                 | 2-way Keccak (ARM NEON / generic)                                                                     |
| `keccak4x/`                                 | 4-way Keccak (AVX2 SIMD256)                                                                           |

### 6.2 `PQCrypto/crypto_kem/` — Key Encapsulation Mechanisms

Each directory contains a `clean/` subfolder with the reference C implementation and an `api.h`.

| Directory           | Algorithm                 | Security Level | Key Sizes                            |
| ------------------- | ------------------------- | -------------- | ------------------------------------ |
| `ml-kem-512/`       | ML-KEM-512 (Kyber)        | Level 1        | PK: 800, SK: 1632, CT: 768, SS: 32   |
| `ml-kem-768/`       | ML-KEM-768 (Kyber)        | Level 3        | PK: 1184, SK: 2400, CT: 1088, SS: 32 |
| `ml-kem-1024/`      | ML-KEM-1024 (Kyber)       | Level 5        | PK: 1568, SK: 3168, CT: 1568, SS: 32 |
| `hqc-128/`          | HQC-128                   | Level 1        | Code-based                           |
| `hqc-192/`          | HQC-192                   | Level 3        | Code-based                           |
| `hqc-256/`          | HQC-256                   | Level 5        | Code-based                           |
| `mceliece348864/`   | Classic McEliece 348864   | Level 1        | Very large PK                        |
| `mceliece348864f/`  | Classic McEliece 348864f  | Level 1        | Fast keygen variant                  |
| `mceliece460896/`   | Classic McEliece 460896   | Level 3        | Very large PK                        |
| `mceliece460896f/`  | Classic McEliece 460896f  | Level 3        | Fast keygen variant                  |
| `mceliece6688128/`  | Classic McEliece 6688128  | Level 5        | Very large PK                        |
| `mceliece6688128f/` | Classic McEliece 6688128f | Level 5        | Fast keygen variant                  |
| `mceliece6960119/`  | Classic McEliece 6960119  | Level 5        | Very large PK                        |
| `mceliece6960119f/` | Classic McEliece 6960119f | Level 5        | Fast keygen variant                  |
| `mceliece8192128/`  | Classic McEliece 8192128  | Level 5+       | Very large PK                        |
| `mceliece8192128f/` | Classic McEliece 8192128f | Level 5+       | Fast keygen variant                  |

**Total KEM variants: 16**

### 6.3 `PQCrypto/crypto_sign/` — Digital Signature Schemes

Each directory contains a `clean/` subfolder with the reference C implementation and an `api.h`.

| Directory                    | Algorithm              | Security Level | Type                       |
| ---------------------------- | ---------------------- | -------------- | -------------------------- |
| `ml-dsa-44/`                 | ML-DSA-44 (Dilithium2) | Level 2        | Lattice-based              |
| `ml-dsa-65/`                 | ML-DSA-65 (Dilithium3) | Level 3        | Lattice-based              |
| `ml-dsa-87/`                 | ML-DSA-87 (Dilithium5) | Level 5        | Lattice-based              |
| `falcon-512/`                | Falcon-512             | Level 1        | NTRU lattice (compact sig) |
| `falcon-1024/`               | Falcon-1024            | Level 5        | NTRU lattice (compact sig) |
| `falcon-padded-512/`         | Falcon-Padded-512      | Level 1        | Fixed-length signatures    |
| `falcon-padded-1024/`        | Falcon-Padded-1024     | Level 5        | Fixed-length signatures    |
| `sphincs-sha2-128f-simple/`  | SPHINCS+-SHA2-128f     | Level 1        | Hash-based (fast, SHA2)    |
| `sphincs-sha2-128s-simple/`  | SPHINCS+-SHA2-128s     | Level 1        | Hash-based (small, SHA2)   |
| `sphincs-sha2-192f-simple/`  | SPHINCS+-SHA2-192f     | Level 3        | Hash-based (fast, SHA2)    |
| `sphincs-sha2-192s-simple/`  | SPHINCS+-SHA2-192s     | Level 3        | Hash-based (small, SHA2)   |
| `sphincs-sha2-256f-simple/`  | SPHINCS+-SHA2-256f     | Level 5        | Hash-based (fast, SHA2)    |
| `sphincs-sha2-256s-simple/`  | SPHINCS+-SHA2-256s     | Level 5        | Hash-based (small, SHA2)   |
| `sphincs-shake-128f-simple/` | SPHINCS+-SHAKE-128f    | Level 1        | Hash-based (fast, SHAKE)   |
| `sphincs-shake-128s-simple/` | SPHINCS+-SHAKE-128s    | Level 1        | Hash-based (small, SHAKE)  |
| `sphincs-shake-192f-simple/` | SPHINCS+-SHAKE-192f    | Level 3        | Hash-based (fast, SHAKE)   |
| `sphincs-shake-192s-simple/` | SPHINCS+-SHAKE-192s    | Level 3        | Hash-based (small, SHAKE)  |
| `sphincs-shake-256f-simple/` | SPHINCS+-SHAKE-256f    | Level 5        | Hash-based (fast, SHAKE)   |
| `sphincs-shake-256s-simple/` | SPHINCS+-SHAKE-256s    | Level 5        | Hash-based (small, SHAKE)  |

**Total Signature variants: 19**

---

## Quick Reference: Algorithm → File Lookup

| Need                            | Include                                                                                                                 |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| SHA-256                         | `primitives/hash/fast/sha256/sha256.h`                                                                                  |
| SHA-512 / SHA-384               | `primitives/hash/fast/sha512/sha512.h`                                                                                  |
| SHA-224                         | `primitives/hash/fast/sha224/sha224.h`                                                                                  |
| BLAKE3                          | `primitives/hash/fast/blake3/blake3.h`                                                                                  |
| BLAKE2b                         | `primitives/hash/fast/blake2b/blake2b.h`                                                                                |
| BLAKE2s                         | `primitives/hash/fast/blake2s/blake2s.h`                                                                                |
| SHA3-256/512, Keccak-256        | `primitives/hash/sponge_xof/sha3/sha3.h`                                                                                |
| SHA3-224                        | `primitives/hash/sponge_xof/sha3_224/sha3_224.h`                                                                        |
| SHA3-384                        | `primitives/hash/sponge_xof/sha3_384/sha3_384.h`                                                                        |
| Keccak-224/384/512              | `primitives/hash/sponge_xof/keccak/keccak.h`                                                                            |
| SHAKE-128/256                   | `primitives/hash/sponge_xof/shake/shake.h`                                                                              |
| Argon2id/i/d                    | `primitives/hash/memory_hard/Argon2id/argon2id.h` (etc.)                                                                |
| MD5                             | `legacy/alive/md5/md5.h`                                                                                                |
| SHA-1                           | `legacy/alive/sha1/sha1.h`                                                                                              |
| RIPEMD-160                      | `legacy/alive/ripemd160/ripemd160.h`                                                                                    |
| Whirlpool                       | `legacy/alive/whirlpool/whirlpool.h`                                                                                    |
| NT Hash                         | `legacy/alive/nt_hash/nt.h`                                                                                             |
| MD2/MD4/SHA-0/HAS-160           | `legacy/unsafe/<algo>/<algo>.h`                                                                                         |
| RIPEMD-128/256/320              | `legacy/unsafe/ripemd<N>/ripemd<N>.h`                                                                                   |
| AES-ECB (legacy)                | `legacy/alive/aes_ecb/aes_ecb.h`                                                                                        |
| AES Core / internal             | `primitives/cipher/aes_core/aes_internal.h`                                                                             |
| AES-CBC/CFB/OFB/CTR/XTS/KW/FPE  | `primitives/cipher/aes_<mode>/aes_<mode>.h`                                                                             |
| AES-GCM/CCM/OCB/EAX/SIV/GCM-SIV | `primitives/aead/aes_<mode>/aes_<mode>.h`                                                                               |
| AES-Poly1305                    | `primitives/aead/aes_poly1305/aes_poly1305.h`                                                                           |
| ChaCha20-Poly1305               | `primitives/aead/chacha20_poly1305/chacha20_poly1305.h`                                                                 |
| AES-CMAC                        | `primitives/mac/aes_cmac/aes_cmac.h`                                                                                    |
| SipHash                         | `primitives/mac/siphash/siphash.h`                                                                                      |
| Ed25519                         | `primitives/ecc/ed25519/ed25519.h`                                                                                      |
| Curve448 / Ed448                | `primitives/ecc/curve448/curve448.h` / `ed448.h`                                                                        |
| Elligator2                      | `primitives/ecc/elligator2/elligator2.h`                                                                                |
| Ristretto255                    | `primitives/ecc/ristretto255/ristretto255.h`                                                                            |
| HKDF / HMAC                     | `PQCrypto/common/hkdf/hkdf.h`                                                                                           |
| DRBG                            | `utils/drbg/drbg.h`                                                                                                     |
| Base64 / Hex / FF70             | `utils/encoding/<format>.h`                                                                                             |
| PoW Client                      | `utils/pow/client/interfaces/pow_client.h`                                                                              |
| PoW Server                      | `utils/pow/server/interfaces/pow_server.h`                                                                              |
| PoW Protocol                    | `utils/pow/client/interfaces/pow_protocol.h`                                                                            |
| PQC KEM Interface               | `utils/pqc/interface_kem.h`                                                                                             |
| PQC Sign Interface              | `utils/pqc/interface_sign.h`                                                                                            |
| All PQC Wrappers                | `utils/pqc_main.c` (link object)                                                                                        |
| Unified Core                    | `include/crypto_core.h`                                                                                                 |
| Leyline Hash Wrappers           | `utils/hash/primitive_fast.h`, `primitive_sponge_xof.h`, `primitive_memory_hard.h`, `legacy_alive.h`, `legacy_unsafe.h` |
