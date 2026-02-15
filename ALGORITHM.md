# NextSSL — Complete Algorithm Catalog

> **Auto-generated reference** — Every algorithm, variant, sub-type, and its accepted arguments are listed below.
> Designed so that any AI agent can understand the full cryptographic surface without reading source files.

---

## Table of Contents

1. [Hash Algorithms](#1-hash-algorithms)
   - 1.1 [Fast Hashes](#11-fast-hashes-primitives-hash-fast)
   - 1.2 [Sponge / XOF Hashes](#12-sponge--xof-hashes-primitives-hash-sponge_xof)
   - 1.3 [Memory-Hard Hashes (Argon2)](#13-memory-hard-hashes-argon2-primitives-hash-memory_hard)
   - 1.4 [Legacy Alive Hashes](#14-legacy-alive-hashes-legacy-alive)
   - 1.5 [Legacy Unsafe Hashes](#15-legacy-unsafe-hashes-legacy-unsafe)
2. [Symmetric Encryption (AES)](#2-symmetric-encryption-aes)
   - 2.1 [AES Core Engine](#21-aes-core-engine)
   - 2.2 [AES Block Cipher Modes](#22-aes-block-cipher-modes-primitives-cipher)
   - 2.3 [AES AEAD Modes](#23-aes-aead-modes-primitives-aead)
   - 2.4 [AES Specialty Modes](#24-aes-specialty-modes)
3. [ChaCha20-Poly1305 AEAD](#3-chacha20-poly1305-aead)
4. [Message Authentication Codes (MAC)](#4-message-authentication-codes-mac)
5. [Elliptic Curve Cryptography (ECC)](#5-elliptic-curve-cryptography-ecc)
   - 5.1 [Ed25519 / Curve25519](#51-ed25519--curve25519)
   - 5.2 [Curve448 / Ed448](#52-curve448--ed448)
   - 5.3 [Elligator2](#53-elligator2)
   - 5.4 [Ristretto255](#54-ristretto255)
6. [Post-Quantum Cryptography (PQC)](#6-post-quantum-cryptography-pqc)
   - 6.1 [ML-KEM (Kyber) — Key Encapsulation](#61-ml-kem-kyber--key-encapsulation)
   - 6.2 [HQC — Key Encapsulation](#62-hqc--key-encapsulation)
   - 6.3 [Classic McEliece — Key Encapsulation](#63-classic-mceliece--key-encapsulation)
   - 6.4 [ML-DSA (Dilithium) — Digital Signatures](#64-ml-dsa-dilithium--digital-signatures)
   - 6.5 [Falcon — Digital Signatures](#65-falcon--digital-signatures)
   - 6.6 [SPHINCS+ — Digital Signatures](#66-sphincs--digital-signatures)
7. [Key Derivation Functions (KDF)](#7-key-derivation-functions-kdf)
8. [DRBG (Deterministic Random Bit Generator)](#8-drbg-deterministic-random-bit-generator)
9. [Encoding Utilities](#9-encoding-utilities)
10. [Proof-of-Work (PoW) Protocol](#10-proof-of-work-pow-protocol)

---

## 1. Hash Algorithms

### 1.1 Fast Hashes (`primitives/hash/fast/`)

#### SHA-224

| Property   | Value               |
| ---------- | ------------------- |
| **Digest** | 28 bytes (224 bits) |
| **Block**  | 64 bytes            |
| **Header** | `sha224.h`          |

```c
void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8_t *data, size_t len);
void sha224_final(SHA224_CTX *ctx, uint8_t hash[28]);
void sha224_hash(const uint8_t *data, size_t len, uint8_t hash[28]);           // one-shot
```

#### SHA-256

| Property   | Value               |
| ---------- | ------------------- |
| **Digest** | 32 bytes (256 bits) |
| **Block**  | 64 bytes            |
| **Header** | `sha256.h`          |

```c
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void sha256(const uint8_t data[], size_t len, uint8_t hash[]);                 // one-shot
// PoW-optimised extras
void sha256_transform_fast(uint32_t state[8], const uint8_t data[64]);
void sha256_double_hash(const uint8_t data[], size_t len, uint8_t hash[]);
void sha256_init_state(uint32_t state[8]);
void sha256_midstate(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final_from_midstate(SHA256_CTX *ctx, const uint8_t remaining[], size_t len, uint8_t hash[]);
```

#### SHA-384 _(inside sha512.h)_

| Property   | Value               |
| ---------- | ------------------- |
| **Digest** | 48 bytes (384 bits) |

```c
void sha384_init(SHA512_CTX *ctx);
void sha384_final(uint8_t digest[48], SHA512_CTX *ctx);
void sha384_hash(const uint8_t *data, size_t len, uint8_t digest[48]);         // one-shot
```

#### SHA-512

| Property   | Value               |
| ---------- | ------------------- |
| **Digest** | 64 bytes (512 bits) |
| **Block**  | 128 bytes           |
| **Header** | `sha512.h`          |

```c
void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
void sha512_final(uint8_t digest[64], SHA512_CTX *ctx);
void sha512_hash(const uint8_t *data, size_t len, uint8_t digest[64]);         // one-shot
```

#### BLAKE2b

| Property   | Value                     |
| ---------- | ------------------------- |
| **Digest** | 1–64 bytes (configurable) |
| **Block**  | 128 bytes                 |
| **Key**    | 0–64 bytes                |
| **Header** | `blake2b.h`               |

```c
int blake2b_init(BLAKE2B_CTX *ctx, size_t outlen);
int blake2b_init_key(BLAKE2B_CTX *ctx, size_t outlen, const void *key, size_t keylen);
int blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen);
int blake2b_final(BLAKE2B_CTX *ctx, void *out, size_t outlen);
// Convenience one-shot (fixed output sizes)
void blake2b_128_hash(const uint8_t *data, size_t len, uint8_t digest[16]);
void blake2b_160_hash(const uint8_t *data, size_t len, uint8_t digest[20]);
void blake2b_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);
void blake2b_384_hash(const uint8_t *data, size_t len, uint8_t digest[48]);
void blake2b_512_hash(const uint8_t *data, size_t len, uint8_t digest[64]);
```

#### BLAKE2s

| Property   | Value                     |
| ---------- | ------------------------- |
| **Digest** | 1–32 bytes (configurable) |
| **Block**  | 64 bytes                  |
| **Key**    | 0–32 bytes                |
| **Header** | `blake2s.h`               |

```c
int blake2s_init(BLAKE2S_CTX *ctx, size_t outlen);
int blake2s_init_key(BLAKE2S_CTX *ctx, size_t outlen, const void *key, size_t keylen);
int blake2s_update(BLAKE2S_CTX *ctx, const void *in, size_t inlen);
int blake2s_final(BLAKE2S_CTX *ctx, void *out, size_t outlen);
// Convenience one-shot
void blake2s_128_hash(const uint8_t *data, size_t len, uint8_t digest[16]);
void blake2s_160_hash(const uint8_t *data, size_t len, uint8_t digest[20]);
void blake2s_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);
```

#### BLAKE3

| Property    | Value                                     |
| ----------- | ----------------------------------------- |
| **Digest**  | 32 bytes default (XOF — arbitrary length) |
| **Block**   | 64 bytes                                  |
| **Key**     | 32 bytes (optional)                       |
| **Version** | 1.8.3                                     |
| **Header**  | `blake3.h`                                |
| **SIMD**    | SSE2, SSE4.1, AVX2, AVX-512 dispatch      |

```c
const char *blake3_version(void);
void blake3_hasher_init(blake3_hasher *self);
void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[32]);
void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context);
void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context, size_t context_len);
void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len);
void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);
void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek, uint8_t *out, size_t out_len);
void blake3_hasher_reset(blake3_hasher *self);
```

---

### 1.2 Sponge / XOF Hashes (`primitives/hash/sponge_xof/`)

#### SHA3-224

| Digest | 28 bytes | Header | `sha3_224.h` |
| ------ | -------- | ------ | ------------ |

```c
void sha3_224_init(SHA3_224_CTX *ctx);
void sha3_224_update(SHA3_224_CTX *ctx, const uint8_t *data, size_t len);
void sha3_224_final(uint8_t digest[28], SHA3_224_CTX *ctx);
void sha3_224_hash(const uint8_t *data, size_t len, uint8_t digest[28]);
```

#### SHA3-256

| Digest | 32 bytes | Header | `sha3.h` |
| ------ | -------- | ------ | -------- |

```c
void sha3_256_init(SHA3_CTX *ctx);
void sha3_update(SHA3_CTX *ctx, const uint8_t *data, size_t len);
void sha3_final(uint8_t *digest, SHA3_CTX *ctx);
void sha3_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);
```

#### SHA3-384

| Digest | 48 bytes | Header | `sha3_384.h` |
| ------ | -------- | ------ | ------------ |

```c
void sha3_384_init(SHA3_384_CTX *ctx);
void sha3_384_update(SHA3_384_CTX *ctx, const uint8_t *data, size_t len);
void sha3_384_final(uint8_t digest[48], SHA3_384_CTX *ctx);
void sha3_384_hash(const uint8_t *data, size_t len, uint8_t digest[48]);
```

#### SHA3-512

| Digest | 64 bytes | Header | `sha3.h` |
| ------ | -------- | ------ | -------- |

```c
void sha3_512_init(SHA3_CTX *ctx);
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t digest[64]);
```

#### Keccak-224 / 256 / 384 / 512

| Variant    | Digest   | Header     |
| ---------- | -------- | ---------- |
| Keccak-224 | 28 bytes | `keccak.h` |
| Keccak-256 | 32 bytes | `sha3.h`   |
| Keccak-384 | 48 bytes | `keccak.h` |
| Keccak-512 | 64 bytes | `keccak.h` |

```c
// Keccak-256 (in sha3.h)
void keccak_256_init(SHA3_CTX *ctx);
void keccak_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);
// Other Keccak variants (in keccak.h)
void keccak_224_init(KECCAK_CTX *ctx);
void keccak_384_init(KECCAK_CTX *ctx);
void keccak_512_init(KECCAK_CTX *ctx);
void keccak_update(KECCAK_CTX *ctx, const uint8_t *data, size_t len);
void keccak_final(uint8_t *digest, KECCAK_CTX *ctx);
void keccak_224_hash(const uint8_t *data, size_t len, uint8_t digest[28]);
void keccak_384_hash(const uint8_t *data, size_t len, uint8_t digest[48]);
void keccak_512_hash(const uint8_t *data, size_t len, uint8_t digest[64]);
```

#### SHAKE-128 / SHAKE-256 (XOF)

| Variant   | Output           | Header    |
| --------- | ---------------- | --------- |
| SHAKE-128 | Arbitrary length | `shake.h` |
| SHAKE-256 | Arbitrary length | `shake.h` |

```c
void shake128_init(SHAKE_CTX *ctx);
void shake256_init(SHAKE_CTX *ctx);
void shake_update(SHAKE_CTX *ctx, const uint8_t *data, size_t len);
void shake_final(SHAKE_CTX *ctx);
void shake_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t outlen);
// One-shot
void shake128_hash(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
void shake256_hash(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
```

---

### 1.3 Memory-Hard Hashes — Argon2 (`primitives/hash/memory_hard/`)

All three variants share the same argument structure.

| Arg                      | Type                    | Description                                          |
| ------------------------ | ----------------------- | ---------------------------------------------------- |
| `t_cost`                 | `uint32_t`              | Time cost (iterations)                               |
| `m_cost`                 | `uint32_t`              | Memory cost in KiB                                   |
| `parallelism`            | `uint32_t`              | Number of threads                                    |
| `pwd` / `pwdlen`         | `const void*`, `size_t` | Password input                                       |
| `salt` / `saltlen`       | `const void*`, `size_t` | Salt bytes                                           |
| `hashlen`                | `size_t`                | Desired output length                                |
| `encoded` / `encodedlen` | `char*`, `size_t`       | _(encoded variant)_ Output buffer for encoded string |

#### Argon2id _(recommended)_

```c
int argon2id_hash_raw(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                      const void *pwd, size_t pwdlen, const void *salt, size_t saltlen,
                      void *hash, size_t hashlen);
int argon2id_hash_encoded(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                          const void *pwd, size_t pwdlen, const void *salt, size_t saltlen,
                          size_t hashlen, char *encoded, size_t encodedlen);
int argon2id_verify(const char *encoded, const void *pwd, size_t pwdlen);
```

#### Argon2i

```c
int argon2i_hash_raw(/* same args as argon2id */);
int argon2i_hash_encoded(/* same args as argon2id */);
int argon2i_verify(const char *encoded, const void *pwd, size_t pwdlen);
```

#### Argon2d

```c
int argon2d_hash_raw(/* same args as argon2id */);
int argon2d_hash_encoded(/* same args as argon2id */);
int argon2d_verify(const char *encoded, const void *pwd, size_t pwdlen);
```

**Supporting files:** `blake2/` (BLAKE2b for internal mixing), `utils/` (core, encoding, threading).

---

### 1.4 Legacy Alive Hashes (`legacy/alive/`)

These are **weakened but still encountered** in real-world systems.

| Algorithm      | Digest          | Block | Header        |
| -------------- | --------------- | ----- | ------------- |
| **MD5**        | 16 B (128 bits) | 64 B  | `md5.h`       |
| **SHA-1**      | 20 B (160 bits) | 64 B  | `sha1.h`      |
| **RIPEMD-160** | 20 B (160 bits) | 64 B  | `ripemd160.h` |
| **Whirlpool**  | 64 B (512 bits) | 64 B  | `whirlpool.h` |
| **NT Hash**    | 16 B (128 bits) | —     | `nt.h`        |
| **AES-ECB**    | _(cipher)_      | 16 B  | `aes_ecb.h`   |

```c
// MD5
void md5_init(MD5_CTX *ctx);  void md5_update(...);  void md5_final(uint8_t[16], ...);
void md5_hash(const uint8_t *data, size_t len, uint8_t digest[16]);

// SHA-1
void sha1_init(SHA1_CTX *ctx);  void sha1_update(...);  void sha1_final(uint8_t[20], ...);
void sha1_hash(const uint8_t *data, size_t len, uint8_t digest[20]);

// RIPEMD-160
void ripemd160_init(...);  void ripemd160_update(...);  void ripemd160_final(uint8_t[20], ...);
void ripemd160_hash(const uint8_t *data, size_t len, uint8_t digest[20]);

// Whirlpool + variants
void whirlpool_hash(const uint8_t *data, size_t len, uint8_t digest[64]);
void whirlpool0_hash(const uint8_t *data, size_t len, uint8_t digest[64]);
void whirlpoolt_hash(const uint8_t *data, size_t len, uint8_t digest[64]);

// NT Hash (Windows NTLM)
void nt_hash(const char *password, uint8_t digest[16]);
void nt_hash_unicode(const uint8_t *password_utf16le, size_t len, uint8_t digest[16]);

// AES-ECB (legacy, no IV)
void AES_ECB_encrypt(const uint8_t* key, const void* pntxt, size_t ptextLen, void* crtxt);
char AES_ECB_decrypt(const uint8_t* key, const void* crtxt, size_t crtxtLen, void* pntxt);
```

---

### 1.5 Legacy Unsafe Hashes (`legacy/unsafe/`)

⚠️ **Cryptographically broken.** Included only for backward compatibility.

| Algorithm      | Digest | Block | Header        |
| -------------- | ------ | ----- | ------------- |
| **MD2**        | 16 B   | 16 B  | `md2.h`       |
| **MD4**        | 16 B   | 64 B  | `md4.h`       |
| **SHA-0**      | 20 B   | 64 B  | `sha0.h`      |
| **HAS-160**    | 20 B   | 64 B  | `has160.h`    |
| **RIPEMD-128** | 16 B   | 64 B  | `ripemd128.h` |
| **RIPEMD-256** | 32 B   | 64 B  | `ripemd256.h` |
| **RIPEMD-320** | 40 B   | 64 B  | `ripemd320.h` |

All share identical API pattern:

```c
void <algo>_init(<ALGO>_CTX *ctx);
void <algo>_update(<ALGO>_CTX *ctx, const uint8_t *data, size_t len);
void <algo>_final(uint8_t digest[<DIGEST_LEN>], <ALGO>_CTX *ctx);
void <algo>_hash(const uint8_t *data, size_t len, uint8_t digest[<DIGEST_LEN>]);
```

---

## 2. Symmetric Encryption (AES)

### 2.1 AES Core Engine

| Property             | Value                                              |
| -------------------- | -------------------------------------------------- |
| **Default Key Size** | 128 bits (`AES___` macro, configurable to 192/256) |
| **Block Size**       | 16 bytes                                           |
| **Header**           | `aes_common.h`, `aes_internal.h`                   |

Core internals: `KeyExpansion`, `rijndaelEncrypt`, `rijndaelDecrypt`, GF(2^128) arithmetic (`mulGF128`, `dotGF128`), CMAC helpers.

### 2.2 AES Block Cipher Modes (`primitives/cipher/`)

| Mode              | Args                                                         | Header      |
| ----------------- | ------------------------------------------------------------ | ----------- |
| **CBC**           | `key`, `iVec[16]`, `pntxt`, `ptextLen`, `crtxt`              | `aes_cbc.h` |
| **CFB**           | `key`, `iVec (block_t)`, `pntxt`, `ptextLen`, `crtxt`        | `aes_cfb.h` |
| **OFB**           | `key`, `iVec (block_t)`, `pntxt`, `ptextLen`, `crtxt`        | `aes_ofb.h` |
| **CTR**           | `key`, `iv`, `pntxt`, `ptextLen`, `crtxt`                    | `aes_ctr.h` |
| **XTS**           | `keys` (double-width), `tweak`, `pntxt`, `ptextLen`, `crtxt` | `aes_xts.h` |
| **KW**            | `kek`, `secret`, `secretLen`, `wrapped`                      | `aes_kw.h`  |
| **FPE (FF1/FF3)** | `key`, `tweak`, `[tweakLen]`, `pntxt`, `ptextLen`, `crtxt`   | `aes_fpe.h` |

Each mode has `encrypt` and `decrypt` functions. FPE default is FF1; FF3 selectable via `FF_X=3`.

### 2.3 AES AEAD Modes (`primitives/aead/`)

All AEAD modes accept: `key`, `nonce`, `aData`, `aDataLen`, `pntxt/crtxt`, `ptextLen/crtxtLen`, `crtxt/pntxt`.

| Mode            | Header          | Notes                  |
| --------------- | --------------- | ---------------------- |
| **AES-GCM**     | `aes_gcm.h`     | NIST standard AEAD     |
| **AES-CCM**     | `aes_ccm.h`     | Counter with CBC-MAC   |
| **AES-OCB**     | `aes_ocb.h`     | Offset Codebook Mode   |
| **AES-EAX**     | `aes_eax.h`     | EAX mode (not EAX')    |
| **AES-GCM-SIV** | `aes_gcm_siv.h` | Nonce-misuse resistant |

```c
void AES_GCM_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* pntxt, size_t ptextLen, void* crtxt);
char AES_GCM_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* crtxt, size_t crtxtLen, void* pntxt);
// CCM, OCB, EAX, GCM-SIV follow identical signature pattern
```

### 2.4 AES Specialty Modes

| Mode             | Header           | Signature                                                  |
| ---------------- | ---------------- | ---------------------------------------------------------- |
| **AES-SIV**      | `aes_siv.h`      | Uses `block_t iv` (SIV-derived), double-key `keys`         |
| **AES-Poly1305** | `aes_poly1305.h` | MAC-only: `AES_Poly1305(keys, nonce, data, dataSize, mac)` |

```c
void AES_SIV_encrypt(const uint8_t* keys, const void* aData, size_t aDataLen, const void* pntxt, size_t ptextLen, block_t iv, void* crtxt);
char AES_SIV_decrypt(const uint8_t* keys, const block_t iv, const void* aData, size_t aDataLen, const void* crtxt, size_t crtxtLen, void* pntxt);
void AES_Poly1305(const uint8_t* keys, const block_t nonce, const void* data, size_t dataSize, block_t mac);
```

---

## 3. ChaCha20-Poly1305 AEAD

| Property    | Value                                  |
| ----------- | -------------------------------------- |
| **Key**     | 32 bytes                               |
| **Nonce**   | 24 bytes (XChaCha20)                   |
| **Header**  | `chacha20_poly1305.h` / `monocypher.h` |
| **Backend** | Monocypher library                     |

```c
void ChaCha20_Poly1305_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* pntxt, size_t ptextLen, void* crtxt);
char ChaCha20_Poly1305_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, size_t aDataLen, const void* crtxt, size_t crtxtLen, void* pntxt);
```

**Optional Ed25519 via Monocypher** (`optional/monocypher-ed25519.h`).

---

## 4. Message Authentication Codes (MAC)

### AES-CMAC

```c
void AES_CMAC(const uint8_t* key, const void* data, size_t dataSize, block_t mac);
// Args: AES key, arbitrary data, output 16-byte MAC
```

### SipHash

```c
int siphash(const void *in, size_t inlen, const void *k, uint8_t *out, size_t outlen);
// k: 16-byte key | outlen: must be 8 or 16
```

### HMAC (via HKDF module)

```c
void pqc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
void hmac_sha3_256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
void hmac_sha3_512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
```

---

## 5. Elliptic Curve Cryptography (ECC)

### 5.1 Ed25519 / Curve25519

| Operation             | Function                                                      |
| --------------------- | ------------------------------------------------------------- |
| Seed generation       | `ed25519_create_seed(unsigned char *seed)`                    |
| Keypair               | `ed25519_create_keypair(pubkey, privkey, seed)`               |
| Sign                  | `ed25519_sign(sig, msg, msg_len, pubkey, privkey)`            |
| Verify                | `ed25519_verify(sig, msg, msg_len, pubkey)` → returns 1 valid |
| Scalar add            | `ed25519_add_scalar(pubkey, privkey, scalar)`                 |
| Key exchange (X25519) | `ed25519_key_exchange(shared, pubkey, privkey)`               |

### 5.2 Curve448 / Ed448

**Curve448 (ECDH):** `wc_curve448_make_key`, `wc_curve448_shared_secret`, `wc_curve448_import_*`, `wc_curve448_export_*`

- Key size: 56 bytes | Deterministic variant: `wc_curve448_make_key_deterministic(key, seed, seedSz)`

**Ed448 (Signatures):** `wc_ed448_make_key`, `wc_ed448_sign_msg`, `wc_ed448_verify_msg`

- Key: 57 bytes priv, 57 bytes pub | Sig: 114 bytes
- Supports `Ed448` and `Ed448ph` (pre-hash) with context bytes

### 5.3 Elligator2

```c
void elligator2_map(uint8_t curve[32], const uint8_t hidden[32]);
int  elligator2_rev(uint8_t hidden[32], const uint8_t public_key[32], uint8_t tweak);
void elligator2_key_pair(uint8_t hidden[32], uint8_t secret_key[32], uint8_t seed[32]);
```

### 5.4 Ristretto255

```c
int ristretto255_is_valid_point(const unsigned char *p);        // 32-byte point
int ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q);
int ristretto255_sub(unsigned char *r, const unsigned char *p, const unsigned char *q);
int ristretto255_from_hash(unsigned char *p, const unsigned char *r);  // 64-byte hash → point
```

---

## 6. Post-Quantum Cryptography (PQC)

All PQC algorithms support **standard** and **deterministic (`_derand`)** modes.

### 6.1 ML-KEM (Kyber) — Key Encapsulation

| Variant         | Security     | Type        |
| --------------- | ------------ | ----------- |
| **ML-KEM-512**  | NIST Level 1 | Lattice KEM |
| **ML-KEM-768**  | NIST Level 3 | Lattice KEM |
| **ML-KEM-1024** | NIST Level 5 | Lattice KEM |

```c
int pqc_mlkem<N>_keypair(uint8_t *pk, uint8_t *sk);
int pqc_mlkem<N>_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);   // coins: 32 bytes
int pqc_mlkem<N>_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_mlkem<N>_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqc_mlkem<N>_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

### 6.2 HQC — Key Encapsulation

| Variant     | Security     |
| ----------- | ------------ |
| **HQC-128** | NIST Level 1 |
| **HQC-192** | NIST Level 3 |
| **HQC-256** | NIST Level 5 |

Same API pattern: `pqc_hqc<N>_keypair`, `_keypair_derand`, `_encaps`, `_encaps_derand`, `_decaps`.

### 6.3 Classic McEliece — Key Encapsulation

| Variant                 | Notes               |
| ----------------------- | ------------------- |
| **mceliece348864**      | Standard            |
| **mceliece348864f**     | Fast key generation |
| **mceliece460896 / f**  | Standard / Fast     |
| **mceliece6688128 / f** | Standard / Fast     |
| **mceliece6960119 / f** | Standard / Fast     |
| **mceliece8192128 / f** | Standard / Fast     |

**10 variants total.** Same API: `pqc_mceliece<PARAM>_keypair`, `_keypair_derand`, `_encaps`, `_encaps_derand`, `_decaps`.

### 6.4 ML-DSA (Dilithium) — Digital Signatures

| Variant       | Security     |
| ------------- | ------------ |
| **ML-DSA-44** | NIST Level 2 |
| **ML-DSA-65** | NIST Level 3 |
| **ML-DSA-87** | NIST Level 5 |

```c
int pqc_mldsa<N>_keypair(uint8_t *pk, uint8_t *sk);
int pqc_mldsa<N>_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);    // seed: 32 bytes
int pqc_mldsa<N>_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int pqc_mldsa<N>_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
int pqc_mldsa<N>_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
```

### 6.5 Falcon — Digital Signatures

| Variant                | Security     | Notes                 |
| ---------------------- | ------------ | --------------------- |
| **Falcon-512**         | NIST Level 1 | Compact signatures    |
| **Falcon-1024**        | NIST Level 5 | Compact signatures    |
| **Falcon-Padded-512**  | NIST Level 1 | Fixed-size signatures |
| **Falcon-Padded-1024** | NIST Level 5 | Fixed-size signatures |

```c
int pqc_falcon<V>_keypair(uint8_t *pk, uint8_t *sk);
int pqc_falcon<V>_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqc_falcon<V>_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int pqc_falcon<V>_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
int pqc_falcon<V>_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
```

### 6.6 SPHINCS+ — Digital Signatures

**Hash-based**, **stateless** post-quantum signatures. **12 parameter sets × 2 hash families = 24 variants:**

| Hash Family | Security Levels | Speed Variants          |
| ----------- | --------------- | ----------------------- |
| **SHA2**    | 128, 192, 256   | `f` (fast), `s` (small) |
| **SHAKE**   | 128, 192, 256   | `f` (fast), `s` (small) |

All "simple" instantiation. API per variant:

```c
int pqc_sphincs<HASH><BITS><SPEED>simple_keypair(uint8_t *pk, uint8_t *sk);
int pqc_sphincs<HASH><BITS><SPEED>simple_keypair_derand(..., const uint8_t *seed);
int pqc_sphincs<HASH><BITS><SPEED>simple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int pqc_sphincs<HASH><BITS><SPEED>simple_sign_derand(..., const uint8_t *rnd);
int pqc_sphincs<HASH><BITS><SPEED>simple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
```

**Full variant list:** `sphincssha2128f`, `sphincssha2128s`, `sphincssha2192f`, `sphincssha2192s`, `sphincssha2256f`, `sphincssha2256s`, `sphincsshake128f`, `sphincsshake128s`, `sphincsshake192f`, `sphincsshake192s`, `sphincsshake256f`, `sphincsshake256s`.

---

## 7. Key Derivation Functions (KDF)

### HKDF (RFC 5869)

| Variant           | PRK Size | Header   |
| ----------------- | -------- | -------- |
| **HKDF-SHA256**   | 32 bytes | `hkdf.h` |
| **HKDF-SHA3-256** | 32 bytes | `hkdf.h` |
| **HKDF-SHA3-512** | 64 bytes | `hkdf.h` |

```c
// HKDF-SHA256
int hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
int hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

// SHA3-256 / SHA3-512 variants: same pattern with hkdf_sha3_256_* / hkdf_sha3_512_*

// TLS 1.3 style
int hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *context, size_t context_len, uint8_t *okm, size_t okm_len);
```

### KDF-SHAKE256 (XOF-based)

```c
void kdf_shake256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
```

---

## 8. DRBG (Deterministic Random Bit Generator)

### CTR_DRBG (AES-256 based) — `utils/drbg/`

```c
void ctr_drbg_init(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len,
                   const uint8_t* personalization, size_t personalization_len);
void ctr_drbg_reseed(CTR_DRBG_CTX* ctx, const uint8_t* entropy, size_t entropy_len,
                     const uint8_t* additional, size_t additional_len);
int  ctr_drbg_generate(CTR_DRBG_CTX* ctx, uint8_t* out, size_t out_len,
                       const uint8_t* additional, size_t additional_len);
void ctr_drbg_free(CTR_DRBG_CTX* ctx);
```

### PQC DRBG (`PQCrypto/common/drbg/`) — AES-256-CTR DRBG for PQClean algorithms

### PQC Randombytes (`PQCrypto/common/randombytes.h`)

```c
int randombytes(uint8_t *output, size_t n);
// Seeding helpers (from pqc_main.c):
void pqc_randombytes_seed(const uint8_t *seed, size_t seed_len);
void pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len);
void pqc_set_udbf(const uint8_t *buf, size_t len);   // User Determined Byte Feeder
```

---

## 9. Encoding Utilities

| Encoding         | Functions                                                                                | Header        |
| ---------------- | ---------------------------------------------------------------------------------------- | ------------- |
| **Base64**       | `base64_encode`, `base64_decode`, `base64_encoded_len`, `base64_decoded_len`             | `base64.h`    |
| **Base64URL**    | `base64url_encode`, `base64url_decode`, `base64url_encoded_len`, `base64url_decoded_len` | `base64url.h` |
| **Hex**          | `hex_encode`, `hex_decode`, `hex_encoded_len`, `hex_decoded_len`                         | `hex.h`       |
| **FlexFrame-70** | `ff70_encode`, `ff70_decode`, `ff70_frame_free`                                          | `ff70.h`      |

### FF70 (Custom Encoding)

```
Format: [Header](Config){Payload|Checksum}[Meta]
Checksum: BLAKE3
```

```c
size_t ff70_encode(const uint8_t *bin, size_t bin_len, const char *header, const char *exclude_chars, const char *meta, char *out, size_t out_len);
int    ff70_decode(const char *ff70_str, ff70_frame_t *frame);   // returns 0, -1, -2, -3
void   ff70_frame_free(ff70_frame_t *frame);
```

---

## 10. Proof-of-Work (PoW) Protocol

### Supported PoW Algorithms

| Enum                | Value | Type                         |
| ------------------- | ----- | ---------------------------- |
| `POW_ALGO_BLAKE3`   | 1     | Primitive Fast               |
| `POW_ALGO_SHA256`   | 2     | Primitive Fast               |
| `POW_ALGO_SHA3_256` | 3     | Sponge/XOF                   |
| `POW_ALGO_ARGON2ID` | 4     | Memory-Hard                  |
| `POW_ALGO_MD5`      | 0x80  | Legacy (disabled by default) |
| `POW_ALGO_SHA1`     | 0x81  | Legacy (disabled by default) |

### Server API

```c
int  pow_server_init_challenge(PoWChallenge *c, PoWAlgorithm algo);
int  pow_server_add_input(PoWChallenge *c, const uint8_t *data, size_t len);
int  pow_server_add_target(PoWChallenge *c, const uint8_t *prefix, size_t prefix_len, uint32_t difficulty);
int  pow_server_tune_difficulty(PoWChallenge *c, uint32_t target_time_ms);
int  pow_server_add_range(PoWChallenge *c, uint8_t min_char, uint8_t max_char);
void pow_server_set_limits(PoWChallenge *c, uint64_t max_tries, uint32_t max_time_ms, uint32_t max_mem_kb);
int  pow_server_set_hash_params(PoWChallenge *c, uint32_t hash_out_len, uint32_t argon2_t_cost,
                                uint32_t argon2_m_cost_kb, uint32_t argon2_parallelism, uint32_t argon2_encoded_len);
int  pow_server_verify(const PoWChallenge *c, const uint8_t *nonce, size_t nonce_len, uint32_t input_index);
```

### Client API

```c
PoWError pow_client_check_safety(const PoWChallenge *c);
PoWError pow_client_solve(const PoWChallenge *c, PoWResult *res);
PoWError pow_client_hash(PoWAlgorithm algo, const PoWHashArgs *args, char *error_msg, size_t error_len, char *warning_msg, size_t warning_len);
```

### Challenge Encoding

```c
int pow_challenge_encode(const PoWChallenge *c, char *out_b64, size_t max_len);
int pow_challenge_decode(const char *b64_str, PoWChallenge *out_c);
void pow_challenge_free(PoWChallenge *challenge);
```

---

## Algorithm Count Summary

| Category                               | Count                                                                          |
| -------------------------------------- | ------------------------------------------------------------------------------ |
| Fast Hashes                            | 7 (SHA-224, SHA-256, SHA-384, SHA-512, BLAKE2b, BLAKE2s, BLAKE3)               |
| Sponge/XOF Hashes                      | 9 (SHA3-224/256/384/512, Keccak-224/256/384/512, SHAKE-128/256)                |
| Memory-Hard Hashes                     | 3 (Argon2id, Argon2i, Argon2d)                                                 |
| Legacy Alive Hashes                    | 5 (MD5, SHA-1, RIPEMD-160, Whirlpool, NT Hash)                                 |
| Legacy Unsafe Hashes                   | 7 (MD2, MD4, SHA-0, HAS-160, RIPEMD-128/256/320)                               |
| AES Cipher Modes                       | 8 (ECB, CBC, CFB, OFB, CTR, XTS, KW, FPE)                                      |
| AES AEAD Modes                         | 7 (GCM, CCM, OCB, EAX, SIV, GCM-SIV, AES-Poly1305)                             |
| Stream AEAD                            | 1 (ChaCha20-Poly1305)                                                          |
| MACs                                   | 3 (AES-CMAC, SipHash, HMAC-SHA256/SHA3)                                        |
| ECC                                    | 4 groups (Ed25519, Curve448/Ed448, Elligator2, Ristretto255)                   |
| PQC KEM                                | 16 variants (3 ML-KEM + 3 HQC + 10 McEliece)                                   |
| PQC Signatures                         | 19 variants (3 ML-DSA + 4 Falcon + 12 SPHINCS+)                                |
| KDF                                    | 5 (HKDF-SHA256, HKDF-SHA3-256, HKDF-SHA3-512, HKDF-Expand-Label, KDF-SHAKE256) |
| DRBG                                   | 2 (CTR_DRBG, PQC DRBG)                                                         |
| Encoding                               | 4 (Base64, Base64URL, Hex, FF70)                                               |
| **Total distinct algorithms/variants** | **~103**                                                                       |
