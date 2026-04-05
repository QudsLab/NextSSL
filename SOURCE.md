# SOURCE.md — NextSSL Library: Full Source Architecture Reference

> Generated from direct reading of all source headers and implementation files in `src/`.  
> Covers **41 registered hash algorithms**, seed system (3 tiers), PoW/DHCM subsystem (41 PoW-eligible algos), **PQC: 3 KEM families (16 variants) + 3 sign families (20 variants)**, modern crypto (8 AEAD modes, 5 asymmetric algos), 7 encodings, and the root interface layer.

---

## Table of Contents

1. [Root Layer](#1-root-layer)
2. [Hash Subsystem — 41 Algorithms total](#2-hash-subsystem--41-algorithms)
   - 2.1 [Hash vtable interface (hash_ops.h)](#21-hash-vtable-interface)
   - 2.2 [Hash Registry — max 64 slots, 41 built-in](#22-hash-registry)
   - 2.3 [Fast SHA-2 Family — 6 algos](#23-fast-sha-2-family)
   - 2.4 [BLAKE Family — 3 algos](#24-blake-family)
   - 2.5 [SHA-3 / Keccak / Sponge — 5 algos](#25-sha-3--keccak--sponge)
   - 2.6 [XOF — Extendable Output Functions — 2 algos](#26-xof--extendable-output-functions)
   - 2.7 [NIST SP 800-185 KMAC — 2 algos](#27-nist-sp-800-185-kmac)
   - 2.8 [Memory-Hard / KDF-as-Hash — 8 algos + 3 optional](#28-memory-hard--kdf-as-hash)
   - 2.9 [Legacy / Weak Hashes — 12 algos](#29-legacy--weak-hashes)
   - 2.10 [Skein Family — 3 algos](#210-skein-family)
   - 2.11 [National Standard: SM3 — 1 algo (conditional)](#211-national-standard-sm3)
   - 2.12 [Usage Flags — 5 bits](#212-usage-flags)
3. [Seed Subsystem — 3-Tier Architecture](#3-seed-subsystem--3-tier-architecture)
   - 3.1 [TIER 1 — OS Entropy — 3 platform backends](#31-tier-1--os-entropy)
   - 3.2 [TIER 2 — Hash-Based CTR Derivation — 41 engines available](#32-tier-2--hash-based-ctr-derivation)
   - 3.3 [TIER 3 — UDBF Test Override — 4 error codes](#33-tier-3--udbf-test-override)
   - 3.4 [Seed Hash Registry — 41 algos, 8 categories](#34-seed-hash-registry)
   - 3.5 [UDBF Rootkey Orchestrator](#35-udbf-rootkey-orchestrator)
4. [PoW Subsystem — Proof of Work — 41 eligible algos](#4-pow-subsystem--proof-of-work)
   - 4.1 [Core Data Structures — 3 structs](#41-core-data-structures)
   - 4.2 [Server Side — 2 API calls](#42-server-side)
   - 4.3 [Client Side — 4 API calls](#43-client-side)
   - 4.4 [DHCM — Dynamic Hash Cost Model — 41 algo enum, 3 difficulty models](#44-dhcm--dynamic-hash-cost-model)
   - 4.5 [PoW Dispatcher](#45-pow-dispatcher)
   - 4.6 [PoW Algorithm Coverage — 7 adapter directories](#46-pow-algorithm-coverage)
5. [PQC Subsystem — Post-Quantum Cryptography — 36 total variants](#5-pqc-subsystem--post-quantum-cryptography)
   - 5.1 [KEM Algorithms — 16 variants (3+3+10)](#51-kem-algorithms)
   - 5.2 [Signature Algorithms — 20 variants (3+4+12+1 legacy)](#52-signature-algorithms)
   - 5.3 [DRBG and Domain Separation](#53-drbg-and-domain-separation)
6. [Modern Crypto Subsystem](#6-modern-crypto-subsystem)
   - 6.1 [Symmetric Encryption — 2 algorithms](#61-symmetric-encryption)
   - 6.2 [AEAD — 8 modes](#62-aead)
   - 6.3 [MAC — 3 primitives](#63-mac)
   - 6.4 [KDF — 2 algorithms](#64-kdf)
   - 6.5 [Asymmetric / Curves — 7 algorithms](#65-asymmetric--curves)
7. [Common Utilities](#7-common-utilities)
   - 7.1 [Encodings — 7 formats](#71-encodings)
   - 7.2 [Secure Memory — 3 platform backends](#72-secure-memory)
   - 7.3 [Input Sanitizer — 4 files](#73-input-sanitizer)
8. [File Map by Directory](#8-file-map-by-directory)

---

## 1. Root Layer

**Path:** `src/root/`

The root layer is the only public-facing surface. External consumers include only `src/root/nextssl.h`.

| File | Purpose |
|------|---------|
| `nextssl.h` | Master umbrella header. Pulls in all root subsystem headers. |
| `nextssl_export.h` | Defines `NEXTSSL_API` export macro. On Windows: `__declspec(dllexport/dllimport)`. On GCC/Clang: `__attribute__((visibility("default")))`. Falls back to empty. Checks for `config.h` first. |
| `hash/root_hash.h` | Exports `nextssl_hash_compute()`, `nextssl_hash_digest_size()`, `nextssl_hash_block_size()`, `nextssl_hash_list()`. One-shot hash over any of the 41 registered algorithms by name. |
| `seed/root_seed.h` | Exported seed derivation API. |
| `modern/root_modern.h` | Exported modern crypto API: symmetric, AEAD, MAC, KDF, asymmetric. |
| `pow/root_pow.h` | Exported PoW server/client API. Thin declarations over `src/pow/pow_api.c` symbols. Includes `pow_types.h` for data structures. |
| `pqc/root_pqc.h` | Exported PQC API. All `nextssl_pqc_*` functions. Guards controlled by same `ENABLE_*` macros as `pqc_main.c`. |

---

## 2. Hash Subsystem — 41 Algorithms

> **Count breakdown:** Fast SHA-2 (6) + BLAKE (3) + SHA-3/Keccak (5) + XOF (2) + KMAC (2) + Memory-Hard (8) + Legacy (12) + Skein (3) = **41 core** | + SM3 (1 conditional) + Pomelo/Makwa/Balloon (3 optional) = up to **45 slots used** | Registry max: `HASH_REGISTRY_MAX = 64`

**Path:** `src/hash/`

### 2.1 Hash vtable interface

**File:** `src/hash/interface/hash_ops.h`

Every hash algorithm is described by a `hash_ops_t` struct (a vtable). The caller allocates an opaque context buffer of at least `HASH_OPS_CTX_MAX` (2048 bytes) and passes it to the three function pointers.

```c
typedef struct hash_ops_s {
    const char  *name;          // e.g. "sha256", "blake3", "argon2id"
    size_t       digest_size;   // hash output length in bytes
    size_t       block_size;    // compression block size in bytes
    uint32_t     usage_flags;   // HASH_USAGE_* bitmask — must be non-zero

    void (*init)  (void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final) (void *ctx, uint8_t *out);

    double   wu_per_eval;   // Work Units per evaluation (relative cost)
    double   mu_per_eval;   // Memory Units per evaluation (non-zero for Argon2/scrypt)
    uint32_t parallelism;   // Argon2 parallelism factor; 1 for all other hashes
} hash_ops_t;
```

- **HASH_OPS_CTX_MAX = 2048** bytes. Sized for `blake3_hasher` (~1912 bytes).
- **HASH_OPS_MAX_BLOCK = 128** bytes. SHA-512 and BLAKE2b use 128-byte blocks.
- All `memory_hard` adapters use an internal `argon2_ops_ctx_t` = `buf[2040] + len[8]` = exactly 2048 bytes.

### 2.2 Hash Registry

> **Slots:** max 64 | **Built-in at init:** 41 core (+ up to 3 optional) | **5 purpose-typed accessors**

**Files:** `src/hash/interface/hash_registry.h`, `src/hash/interface/hash_registry.c`

- `HASH_REGISTRY_MAX = 64` concurrent registrations.
- `hash_registry_init()` — registers all built-in algorithms. Safe to call multiple times (no-op after first).
- `hash_register(ops)` — register an algorithm. Returns -1 if `usage_flags == 0`.
- `hash_lookup(name)` — case-sensitive name lookup. Returns `NULL` if not found.
- **Purpose-typed accessors** (check flag before returning, defence-in-depth):
  - `hash_for_hmac(name)` — checks `HASH_USAGE_HMAC`
  - `hash_for_pbkdf2(name)` — checks `HASH_USAGE_PBKDF2`
  - `hash_for_hkdf(name)` — checks `HASH_USAGE_HKDF`
  - `hash_for_pow(name)` — checks `HASH_USAGE_POW`
  - `hash_for_seed(name)` — checks `HASH_USAGE_SEED`

### 2.3 Fast SHA-2 Family — 6 algorithms

**Path:** `src/hash/fast/`

| Name | Digest | Block | wu_per_eval | Notes |
|------|--------|-------|-------------|-------|
| `sha224` | 28 | 64 | 1.0 | SHA-224 |
| `sha256` | 32 | 64 | 1.2 | SHA-256 |
| `sha384` | 48 | 128 | 2.0 | SHA-384; shares `SHA512_CTX` |
| `sha512` | 64 | 128 | 2.0 | SHA-512 |
| `sha512-224` | 28 | 128 | 2.0 | FIPS 180-4 §5.3.6.1; shares `sha512_update` |
| `sha512-256` | 32 | 128 | 2.0 | FIPS 180-4 §5.3.6.2; shares `sha512_update` |

All 6 carry `usage_flags = HASH_USAGE_ALL` (valid for HMAC, PBKDF2, HKDF, PoW, Seed).

### 2.4 BLAKE Family — 3 algorithms

**Path:** `src/hash/blake/`

| Name | Digest | Block | wu_per_eval | Notes |
|------|--------|-------|-------------|-------|
| `blake2b` | 64 | 128 | 0.8 | BLAKE2b-512 default output |
| `blake2s` | 32 | 64 | 0.5 | BLAKE2s-256 default output |
| `blake3` | 32 | 64 | 0.4 | BLAKE3-256; hasher context ~1912 bytes |

BLAKE3 includes AVX2, AVX512, SSE2, SSE4.1 dispatch files (`blake3_avx2.c`, `blake3_avx512.c`, `blake3_dispatch.c`, `blake3_sse2.c`, `blake3_sse41.c`, `blake3_portable.c`). All 3 carry `HASH_USAGE_ALL`.

### 2.5 SHA-3 / Keccak / Sponge — 5 algorithms

**Path:** `src/hash/sponge/`

| Name | Digest | Block (rate) | wu_per_eval | Notes |
|------|--------|--------------|-------------|-------|
| `sha3-224` | 28 | 144 | 1.5 | Rate = 1152 bits |
| `sha3-256` | 32 | 136 | 1.5 | Rate = 1088 bits; uses shared `SHA3_CTX` |
| `sha3-384` | 48 | 104 | 1.8 | Rate = 832 bits |
| `sha3-512` | 64 | 72 | 2.0 | Rate = 576 bits; uses shared `SHA3_CTX` |
| `keccak256` | 32 | 136 | 1.5 | Pre-NIST Keccak; uses `sha3_final_custom(..., 0x01)` |

All 5 carry `HASH_USAGE_ALL`.

### 2.6 XOF — Extendable Output Functions — 2 algorithms

**Path:** `src/hash/sponge_xof/`

| Name | Fixed Output | Block (rate) | wu_per_eval | Usage Flags |
|------|-------------|--------------|-------------|-------------|
| `shake128` | 32 | 168 | 1.5 | `POW \| SEED` |
| `shake256` | 64 | 136 | 2.0 | `POW \| SEED` |

XOF output is fixed within `hash_ops_t` (32/64 bytes). Full variable output available via direct `shake_squeeze()` calls. Not valid for HMAC/PBKDF2/HKDF.

### 2.7 NIST SP 800-185 KMAC — 2 algorithms

**Path:** `src/hash/sponge/sp800_185/kmac.h`

| Name | Output | Block (rate) | wu_per_eval | Usage Flags |
|------|--------|--------------|-------------|-------------|
| `kmac128` | 32 | 168 | 1.5 | `HMAC \| POW \| SEED` |
| `kmac256` | 64 | 136 | 2.0 | `HMAC \| POW \| SEED` |

Unkeyed mode (empty key, empty S) — equivalent to cSHAKE with N="KMAC". Not valid for PBKDF2 or HKDF (wrapping KMAC in HMAC-based constructs is undefined).

### 2.8 Memory-Hard / KDF-as-Hash — 8 core + 3 optional

**Path:** `src/hash/memory_hard/`

These are KDF adapters wrapped in the `hash_ops_t` interface. They accumulate all `update()` data in a fixed buffer and call the full KDF on `final()`.

**RESTRICTION:** Only valid for `seed_hash_derive_ex()` CTR seeding where total input is ≤ 2040 bytes. NOT for HMAC, HKDF, or PBKDF2.

Internal context: `argon2_ops_ctx_t = { buf[2040], len }` — fits exactly in 2048-byte HASH_OPS_CTX_MAX.

Fixed internal parameters:
- `t_cost = 2` (time cost)
- `m_cost = 65536` (64 MiB)
- `parallelism = 1`
- Salt: 16 zero bytes (adapter is for KDF/seeding, not password storage)

| Name | Digest | wu_per_eval | mu_per_eval | Notes |
|------|--------|-------------|-------------|-------|
| `argon2id` | 32 | 5000.0 | 64.0 | Hybrid data/independent — recommended |
| `argon2i` | 32 | 5000.0 | 64.0 | Data-independent memory access |
| `argon2d` | 32 | 5000.0 | 64.0 | Data-dependent; GPU-resistant |
| `scrypt` | 32 | variable | variable | Colin Percival |
| `yescrypt` | 32 | variable | variable | Replaces balloon in this build |
| `catena` | 32 | variable | variable | Graph-based; cache-erasure |
| `lyra2` | 32 | variable | variable | Sponge-based; low memory mode |
| `bcrypt` | 32 | variable | 0.0 | Cost factor based; Blowfish |

Optional (feature-guarded):
- `pomelo` — `#ifdef NEXTSSL_HAS_POMELO`
- `makwa` — `#ifdef NEXTSSL_HAS_MAKWA`
- `balloon` — `#ifdef NEXTSSL_HAS_BALLOON` (in seed system)

All memory-hard hashes: `usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED`.

### 2.9 Legacy / Weak Hashes — 12 algorithms

**Path:** `src/hash/legacy/`

> ⚠️ These are cryptographically broken or weak. Registered for correctness testing and PoW use only.

| Name | Digest | Block | wu_per_eval | Usage Flags | Notes |
|------|--------|-------|-------------|-------------|-------|
| `sha1` | 20 | 64 | 0.8 | ALL | SHA-1 (NIST, broken) |
| `sha0` | 20 | 64 | 0.8 | `POW\|SEED\|HMAC` | SHA-0 (pre-publication SHA) |
| `md5` | 16 | 64 | 0.5 | `POW\|SEED\|HMAC` | MD5 (broken collision) |
| `md4` | 16 | 64 | 0.4 | `POW\|SEED\|HMAC` | MD4 |
| `md2` | 16 | 16 | 2.0 | `POW\|SEED\|HMAC` | MD2 |
| `nt` | 16 | 64 | 0.5 | `POW\|SEED\|HMAC` | NTLM hash: MD4(UTF-16LE(pass)); accumulator adapter |
| `ripemd128` | 16 | 64 | 1.0 | ALL | RIPEMD-128 |
| `ripemd160` | 20 | 64 | 1.2 | ALL | RIPEMD-160 (Bitcoin key hashing) |
| `ripemd256` | 32 | 64 | 1.3 | ALL | RIPEMD-256 |
| `ripemd320` | 40 | 64 | 1.5 | ALL | RIPEMD-320 |
| `whirlpool` | 64 | 64 | 3.0 | ALL | Whirlpool (ISO/IEC 10118-3) |
| `has160` | 20 | 64 | 0.9 | `POW\|SEED\|HMAC` | Korean KISA standard (HAS-160) |

**NT-HASH special note:** No native streaming API in `nt.h`. Uses same `buf[2040]+len` accumulator pattern as Argon2 adapters. Caller must supply raw UTF-16LE bytes.

### 2.10 Skein Family — 3 algorithms

**Path:** `src/hash/skein/`

| Name | Digest | wu_per_eval | Notes |
|------|--------|-------------|-------|
| `skein256` | 32 | 1.2 | Skein-256 (Doug Whiting; Werner Dittmann wrapper, MIT) |
| `skein512` | 64 | 2.0 | Skein-512 |
| `skein1024` | 128 | 4.0 | Skein-1024 |

All 3 carry `HASH_USAGE_ALL`. Threefish used internally as the block cipher.

### 2.11 National Standard: SM3 — 1 algorithm (conditional)

**Path:** `src/hash/fast/sm3/`

| Name | Digest | wu_per_eval | Condition |
|------|--------|-------------|-----------|
| `sm3` | 32 | 1.5 | `#ifdef NEXTSSL_HAS_GMSSL` |

Chinese GB/T 32905-2016 hash standard. Only registered and compiled when `NEXTSSL_HAS_GMSSL` is defined.

### 2.12 Usage Flags — 5 bits

Defined in `src/hash/interface/hash_ops.h`:

| Flag | Bit | Meaning |
|------|-----|---------|
| `HASH_USAGE_HMAC` | 0 | Valid for RFC 2104 HMAC |
| `HASH_USAGE_PBKDF2` | 1 | Valid for PBKDF2-HMAC (RFC 2898) |
| `HASH_USAGE_HKDF` | 2 | Valid for HKDF (RFC 5869) |
| `HASH_USAGE_POW` | 3 | Valid for PoW backend |
| `HASH_USAGE_SEED` | 4 | Valid for seed accumulation |
| `HASH_USAGE_ALL_KDF` | composite | HMAC \| PBKDF2 \| HKDF |
| `HASH_USAGE_ALL` | composite | ALL_KDF \| POW \| SEED |

---

## 3. Seed Subsystem — 3-Tier Architecture

> **Tiers:** 3 | **OS RNG backends:** 3 (Windows/Linux/macOS) | **Hash engines available:** 41 | **UDBF error codes:** 4 | **CTR counter size:** 4 bytes big-endian | **Seed hash categories:** 8

**Path:** `src/seed/`

The seed system has three tiers. `root/seed/root_seed.h` is the public entry point.

```
TIER 1: seed_derive_random()  — OS RNG (pure entropy)
TIER 2: seed_hash_derive()    — deterministic CTR-mode hash expansion
TIER 3: UDBF test override    — inject KAT test vectors (test-mode only)
```

### 3.1 TIER 1 — OS Entropy — 3 platform backends

**Path:** `src/seed/random/`

**Files:** `entropy.h`, `seed_derive_random.h`

- `entropy_getrandom(out, len)` — OS cryptographic RNG.
  - Windows: `BCryptGenRandom()`
  - Linux: `getrandom()`
  - macOS: `arc4random_buf()`
  - Returns 0 on success, -1 on failure.
- `entropy_available()` — returns 1 if OS RNG is available.
- `seed_derive_random(out, len)` — thin wrapper; returns 0/-1.

### 3.2 TIER 2 — Hash-Based CTR Derivation — 41 engine choices

**Path:** `src/seed/hash/`

**Files:** `seed_core.h`, `seed_types.h`, `ctr_mode.h`, `hash_internal.h`

```
Block_i = Hash(seed || ctx_label || big_endian_counter_i)
Output  = concat(Block_1, Block_2, ...) truncated to out_len
```

**`seed_hash_config_t`** (from `seed_types.h`):
- `engine` — pointer to `hash_ops_t` vtable; NULL defaults to SHA-512.
- `ctx_label` — domain separation label string.

**`seed_hash_derive(cfg, seed, seed_len, out, out_len)`**:
1. Checks TIER 3 (UDBF) first; if active, reads test vector by label.
2. Otherwise runs standard CTR expansion.
3. Temporarily buffers are securely wiped before return.
4. Results are fully deterministic: same seed + label → same output.
5. Max output: `SEED_MAX_OUTPUT_LEN = 1 MB`.
6. Counter starts at `SEED_CTR_START = 1`, encoded as 4-byte big-endian.

**`ctr_mode_expand(engine, seed, seed_len, ctx_label, ctx_label_len, out, out_len)`** — the raw expansion function.

### 3.3 TIER 3 — UDBF Test Override — 4 error codes, 4 API functions

**Path:** `src/seed/udbf/`  
**Files:** `udbf.h`, `udbf_errors.h`

**UDBF** = User-Defined Byte Feed. Test-mode only. Injects KAT (Known-Answer Test) vectors.

Binary format:
```
[uint32_le: total_len]
[entries... each: uint8:label_len | label_bytes | uint32_le:value_len | value_bytes]
```

API:
- `udbf_feed(data, len)` — load test vector data (≤ 1 MB, once only).
- `udbf_read(label, out, olen)` — retrieve labeled value.
- `seed_udbf_is_active()` — returns 1 if UDBF is loaded.
- `udbf_wipe()` — securely erases stored data, allows reload.

Error codes (`udbf_result_t`):
- `UDBF_OK = 0`
- `UDBF_ERR_ALREADY_LOADED = -1`
- `UDBF_ERR_NO_DATA = -2`
- `UDBF_ERR_LABEL_NOT_FOUND = -3`
- `UDBF_ERR_TOO_LARGE = -4`

### 3.4 Seed Hash Registry — 41 algorithms, 8 categories

**Path:** `src/seed/hash/`  
**Files:** `hash_ops.h`, `hash_registry.h`

`HASH_REGISTRY[]` — flat array of `hash_registry_entry_t { name, ops, category }`.

Categories:
- `HASH_CAT_BLAKE = 0` — BLAKE2b, BLAKE2s, BLAKE3
- `HASH_CAT_FAST = 1` — SHA-2 family, SM3
- `HASH_CAT_LEGACY = 2` — SHA-0/1, MD2/4/5, RIPEMD, etc.
- `HASH_CAT_MEMORY_HARD = 3` — Argon2, scrypt, bcrypt, catena, yescrypt
- `HASH_CAT_SPONGE = 4` — SHA-3, Keccak
- `HASH_CAT_XOF = 5` — SHAKE-128/256
- `HASH_CAT_SKEIN = 6` — Skein-256/512/1024, Threefish
- `HASH_CAT_KMAC = 7` — NIST SP 800-185 KMAC

`hash_lookup_by_name(algo_name)` — case-sensitive lookup. Names use lowercase with hyphens.

All 41 vtable externs are re-declared here for use by the seed system.

### 3.5 UDBF Rootkey Orchestrator

**Path:** `src/seed/udbf/`  
**File:** `rootkey.h`

`rootkey_get(mode, label, coins, coins_len, out, out_len)` — domain-separated seed derivation. Used by `pqc_main.c` to ensure that the same coin bytes fed to different PQC algorithms produce independent DRBG streams.

Mode: `ROOTKEY_MODE_SEED` — derives from HKDF with the label as the info field.

---

## 4. PoW Subsystem — Proof of Work

> **PoW-eligible algorithms:** 41 (all DHCM-enumerated) | **3 core structs** | **3 difficulty models** | **7 adapter directories** | **Server API:** 2 calls | **Client API:** 4 calls | **Reject reasons:** 6

**Path:** `src/pow/`

### 4.1 Core Data Structures — 3 structs

**File:** `src/pow/core/pow_types.h`

**`pow_challenge_t`** (server → client):
```c
uint8_t  version;               // protocol version (1)
uint8_t  challenge_id[16];      // random UUID
char     algorithm_id[32];      // canonical hyphen-form: "sha3-256", "blake3"
uint8_t  context[256];          // server-controlled context bytes
size_t   context_len;
uint8_t  target[64];            // difficulty target: hash < target (big-endian)
size_t   target_len;
uint32_t difficulty_bits;       // leading zero bits required
uint64_t wu;                    // expected Work Units (from DHCM)
uint64_t mu;                    // expected Memory Units KB (from DHCM)
uint64_t expires_unix;          // expiry timestamp (Unix seconds)
```

**`pow_solution_t`** (client → server):
```c
uint8_t  challenge_id[16];      // must match challenge
uint64_t nonce;                 // winning nonce
uint8_t  hash_output[64];       // hash(context || decimal_nonce_string)
size_t   hash_output_len;
double   solve_time_seconds;
uint64_t attempts;
```

**`pow_adapter_t`** (per-algorithm vtable):
```c
const char *name;               // canonical hyphen-form name
int (*hash)(input, len, params, out);
int (*get_cost)(difficulty_bits, DHCMResult *result);
```

### 4.2 Server Side — 2 API calls

**Path:** `src/pow/server/`

- `pow_server_generate_challenge(config, algorithm_id, context, context_len, difficulty_bits, out)` — generates a new challenge. Rejects if WU exceeds `config->max_wu_per_challenge`. Uses DHCM to populate `wu` and `mu` fields.
- `pow_server_verify_solution(challenge, solution, out_valid)` — re-hashes `context || nonce_decimal_string`, checks `hash < target`, verifies `challenge_id` match and expiry.

**`pow_config_t`**:
- `default_difficulty_bits`, `max_wu_per_challenge`, `challenge_ttl_seconds`
- `allowed_algos[64]` — whitelist of algorithm names
- `max_challenges_per_ip`, `rate_limit_window_seconds`

### 4.3 Client Side — 4 API calls + 2 utility headers

**Path:** `src/pow/client/`

- `pow_client_parse_challenge(challenge_b64, out)` — decode base64-JSON challenge string. Errors: -2 decode fail, -3 unsupported version, -4 algorithm not registered.
- `pow_client_solve(challenge, out)` — brute-force nonce search. Hash input: `context || sprintf(nonce)`. Errors: -2 nonce exhausted, -3 hash error, -5 context too large.
- `pow_client_check_limits(challenge, max_wu, max_mu_kb, max_time_seconds, out_acceptable)` — capability check using embedded WU/MU.
- `pow_client_reject_reason(challenge, out_reason)` — returns `pow_reject_reason_t`:
  - `POW_REJECT_ALGO_UNSUPPORTED`, `POW_REJECT_TOO_HARD_WU`, `POW_REJECT_TOO_HARD_MU`, `POW_REJECT_TOO_HARD_TIME`, `POW_REJECT_EXPIRED`, `POW_REJECT_INVALID_FORMAT`

**`pow_timer.h`** — `pow_timer_start()` / `pow_timer_elapsed()` — portable high-resolution solve timer.

**`pow_difficulty.h`**:
- `pow_difficulty_bits_to_target(bits, out_target, len)` — encode leading-zero-bit difficulty as target byte array.
- `pow_hash_meets_target(hash, target, len)` — returns 1 if `hash < target` (big-endian).

**`pow_parser.h`**:
- `pow_algo_name_normalise(name)` — converts underscores to hyphens in-place (`"sha3_256"` → `"sha3-256"`).
- `pow_challenge_encode/decode()`, `pow_solution_encode/decode()` — base64-JSON serialize.

### 4.4 DHCM — Dynamic Hash Cost Model — 41 algo enum, 3 difficulty models

> **Algorithm enum count:** 41 (6+3+7+2+8+3+12) | **Difficulty models:** 3 | **DHCMResult fields:** 7 | **Cost model version:** 2.0.0

**Path:** `src/pow/dhcm/`  
**Files:** `dhcm_types.h`, `dhcm_core.h`, `dhcm_difficulty.h`, `dhcm_math.h`

The DHCM calculates expected WU (Work Units) and MU (Memory Units) for any algorithm at any difficulty setting. All 41 PoW-eligible algorithms are listed with no feature guards.

**`DHCMAlgorithm` enum** — grouped by high byte:

| Group | High Byte | Algorithms |
|-------|-----------|------------|
| Fast SHA-2 | 0x01 | SHA-224/256/384/512, SHA-512/224, SHA-512/256 |
| BLAKE | 0x02 | BLAKE2b, BLAKE2s, BLAKE3 |
| SHA-3/Keccak/KMAC | 0x03 | SHA3-224/256/384/512, Keccak256, KMAC128/256 |
| Sponge XOF | 0x04 | SHAKE128, SHAKE256 |
| Memory-Hard | 0x05 | Argon2id/i/d, scrypt, yescrypt, catena, Lyra2, bcrypt |
| Skein | 0x06 | Skein-256/512/1024 |
| Legacy | 0x07 | SHA-1, SHA-0, MD5, MD4, MD2, NT, RIPEMD-128/160/256/320, Whirlpool, HAS-160 |

**Difficulty Models:**
- `DHCM_DIFFICULTY_TARGET_BASED` — `E[N] = 2^target_leading_zeros` (standard hash PoW).
- `DHCM_DIFFICULTY_ITERATION_BASED` — cost embedded in algo params (Argon2, bcrypt).
- `DHCM_DIFFICULTY_NONE` — single-hash, no search (verify only).

**`DHCMParams`**: algorithm + model + target_leading_zeros + iterations + memory_kb + parallelism + bcrypt_cost + input_size + output_size.

**`DHCMResult`**: work_units_per_eval, memory_units_per_eval, expected_trials, total_work_units, total_memory_units, verification_work_units, algorithm_name (string), cost_model_version ("2.0.0").

**`dhcm_core_calculate(params, result)`** — fills all DHCMResult fields. Returns -2 for unknown algorithm.

**`dhcm_expected_trials(model, target_zeros)`** — returns `2.0^target_zeros` for target-based, `1.0` for iteration-based.

### 4.5 PoW Dispatcher

**File:** `src/pow/dispatcher.h` / `dispatcher.c`

`pow_adapter_get(name)` — resolves a canonical hyphen-form algorithm name to its `pow_adapter_t`. Returns NULL if not registered. Each adapter's `hash()` function calls `hash_lookup(name)` from the main hash registry and runs `init/update/final`.

### 4.6 PoW Algorithm Coverage — 7 adapter directories, 41 adapters

PoW backend subdirectories mirror the hash subsystem structure:

```
src/pow/fast/        — SHA-2 family adapters
src/pow/blake/       — BLAKE2b, BLAKE2s, BLAKE3 adapters
src/pow/sponge/      — SHA-3 / Keccak adapters
src/pow/sponge_xof/  — SHAKE adapters
src/pow/skein/       — Skein adapters
src/pow/legacy/      — SHA-1, SHA-0, MD5, MD4, MD2, NT, RIPEMD, Whirlpool, HAS-160 adapters
src/pow/memory_hard/ — Argon2, scrypt, yescrypt, catena, Lyra2, bcrypt adapters
```

All 41 DHCM-enumerated algorithms have corresponding PoW adapters.

---

## 5. PQC Subsystem — Post-Quantum Cryptography

> **KEM families:** 3 (ML-KEM, HQC, McEliece) | **KEM variants total:** 16 (3+3+10) | **Sign families:** 3 (ML-DSA, Falcon, SPHINCS+) | **Sign variants total:** 19 (3+4+12) | **Compile guards:** 6 (`ENABLE_ML_KEM`, `ENABLE_ML_DSA`, `ENABLE_FALCON`, `ENABLE_HQC`, `ENABLE_MCELIECE`, `ENABLE_SPHINCS`) | **Operations per variant:** 5 (keypair, keypair_derand, encaps/sign, encaps_derand/sign_derand, decaps/verify)

**Path:** `src/pqc/`  
**Files:** `pqc_main.c`, `interface_kem.h`, `interface_sign.h`, `root/pqc/root_pqc.h`

All PQC operations are guarded by compile-time flags: `ENABLE_ML_KEM`, `ENABLE_ML_DSA`, `ENABLE_FALCON`, `ENABLE_HQC`, `ENABLE_MCELIECE`, `ENABLE_SPHINCS`.

### 5.1 KEM Algorithms — 16 variants across 3 families

**ML-KEM (Kyber)** — 3 variants — `#ifdef ENABLE_ML_KEM` — NIST FIPS 203

| Variant | Security Level | Path |
|---------|----------------|------|
| ML-KEM-512 | Level 1 (128-bit) | `kem/ml-kem-512/ref/` |
| ML-KEM-768 | Level 3 (192-bit) | `kem/ml-kem-768/ref/` |
| ML-KEM-1024 | Level 5 (256-bit) | `kem/ml-kem-1024/ref/` |

Each variant exposes: `keypair`, `keypair_derand`, `encaps`, `encaps_derand`, `decaps`.

**HQC** — 3 variants — `#ifdef ENABLE_HQC` — code-based KEM

| Variant | Security Level | Path |
|---------|----------------|------|
| HQC-128 | Level 1 | `kem/hqc-128/ref/` |
| HQC-192 | Level 3 | `kem/hqc-192/ref/` |
| HQC-256 | Level 5 | `kem/hqc-256/ref/` |

**Classic McEliece** — 10 variants — `#ifdef ENABLE_MCELIECE` — code-based KEM, large keys

| Variant | Path |
|---------|------|
| mceliece348864 | `kem/mceliece348864/ref/` |
| mceliece348864f | `kem/mceliece348864f/ref/` |
| mceliece460896 | `kem/mceliece460896/ref/` |
| mceliece460896f | `kem/mceliece460896f/ref/` |
| mceliece6688128 | `kem/mceliece6688128/ref/` |
| mceliece6688128f | `kem/mceliece6688128f/ref/` |
| mceliece6960119 | `kem/mceliece6960119/ref/` |
| mceliece6960119f | `kem/mceliece6960119f/ref/` |
| mceliece8192128 | `kem/mceliece8192128/ref/` |
| mceliece8192128f | `kem/mceliece8192128f/ref/` |

Each exposes: `keypair`, `keypair_derand`, `encaps`, `encaps_derand`, `decaps`.

Legacy Kyber interface (from `interface_kem.h`): `nextssl_kyber512/768/1024_keypair/enc/dec()` — direct wrappers.

### 5.2 Signature Algorithms — 19 variants across 3 families

**ML-DSA (Dilithium)** — 3 variants — `#ifdef ENABLE_ML_DSA` — NIST FIPS 204

| Variant | Security Level | Path |
|---------|----------------|------|
| ML-DSA-44 | Level 2 | `sign/ml-dsa-44/ref/` |
| ML-DSA-65 | Level 3 | `sign/ml-dsa-65/ref/` |
| ML-DSA-87 | Level 5 | `sign/ml-dsa-87/ref/` |

Each exposes: `keypair`, `keypair_derand`, `sign`, `sign_derand`, `verify`.

Legacy Dilithium interface (from `interface_sign.h`): `nextssl_dilithium2/3/5_keypair/sign/verify()`.

**Falcon** — 4 variants — `#ifdef ENABLE_FALCON` — NIST Round 3 finalist (lattice-based)

| Variant | Path |
|---------|------|
| Falcon-512 | `sign/falcon-512/ref/` |
| Falcon-1024 | `sign/falcon-1024/ref/` |
| Falcon-Padded-512 | `sign/falcon-padded-512/ref/` |
| Falcon-Padded-1024 | `sign/falcon-padded-1024/ref/` |

Each exposes: `keypair`, `keypair_derand`, `sign`, `sign_derand`, `verify`.

**SPHINCS+** — 12 variants — `#ifdef ENABLE_SPHINCS` — hash-based signatures (NIST FIPS 205)

12 variants (2 hash × 3 security levels × 2 size trade-offs × simple only):

| Hash | Level | Mode | Variant |
|------|-------|------|---------|
| SHA-2 | 128 | f (fast) | sphincs-sha2-128f-simple |
| SHA-2 | 128 | s (small) | sphincs-sha2-128s-simple |
| SHA-2 | 192 | f | sphincs-sha2-192f-simple |
| SHA-2 | 192 | s | sphincs-sha2-192s-simple |
| SHA-2 | 256 | f | sphincs-sha2-256f-simple |
| SHA-2 | 256 | s | sphincs-sha2-256s-simple |
| SHAKE | 128 | f | sphincs-shake-128f-simple |
| SHAKE | 128 | s | sphincs-shake-128s-simple |
| SHAKE | 192 | f | sphincs-shake-192f-simple |
| SHAKE | 192 | s | sphincs-shake-192s-simple |
| SHAKE | 256 | f | sphincs-shake-256f-simple |
| SHAKE | 256 | s | sphincs-shake-256s-simple |

SPHINCS+ internal components: WOTS+, FORS, Merkle tree, hypertree. Reference params in `params.h` (SPHINCS+-SHAKE256-simple-AVX2 example: SPX_N=32, height=64, D=8, FORS_HEIGHT=14, FORS_TREES=22).

Legacy SPHINCS+ interface: `nextssl_sphincs_shake_128f_simple_keypair/sign/verify()`.

### 5.3 DRBG and Domain Separation

`pqc_main.c` provides a global DRBG seeding system with domain separation to prevent identical entropy from producing the same keys across algorithms.

```c
// Internal: derive 32-byte domain-separated seed from coins+label, then seed DRBG
static void pqc_seed_from_coins(const char *label, const uint8_t *coins, size_t coins_len);
```

Internally calls: `rootkey_get(ROOTKEY_MODE_SEED, label, coins, coins_len, seed, 32)` — HKDF-based (using `pqc/common/hkdf/`), then `pqc_randombytes_seed(seed, 32)`. Seed buffer is wiped after use via volatile pointer loop.

Public DRBG API:
- `pqc_drbg_seed(seed, salt, info)` — HKDF-extract then HKDF-expand to produce DRBG key.
- `pqc_drbg_reseed(seed, salt)` — re-key DRBG.
- `pqc_udbf_feed(buf, len)` — inject test vectors into PQC DRBG via `pqc_set_udbf()`.
- `pqc_randombytes(out, out_len)` — get random bytes from the DRBG.

---

## 6. Modern Crypto Subsystem

> **Symmetric modes:** 2 (AES-CBC, ChaCha20) | **AEAD modes:** 8 | **MAC primitives:** 3 | **KDF algorithms:** 2 | **Asymmetric curves:** 8 (Ed25519, X25519, EdDSA-Mono, Ed448, X448, P-256, P-384, P-521)

**Path:** `src/modern/`

Public API via `src/root/modern/root_modern.h`.

### 6.1 Symmetric Encryption — 2 ciphers

**Path:** `src/modern/symmetric/`

| Algorithm | Notes |
|-----------|-------|
| AES-CBC | `nextssl_sym_aes_cbc_encrypt/decrypt()`. key_len: 16/24/32, IV: 16 bytes. Length-preserving for complete blocks; caller handles padding. |
| AES (internal) | `aes_internal.h` — shared AES block cipher used by AEAD/MAC modes. |
| ChaCha20 | Stream cipher (via Monocypher). |

### 6.2 AEAD — 8 modes

**Path:** `src/modern/aead/`

| Algorithm | File | Notes |
|-----------|------|-------|
| AES-GCM | `aes_gcm.h` | `nextssl_aead_aes_gcm_encrypt/decrypt()`. key_len: 16/24/32, nonce: 12 bytes. Returns -1 on auth failure. |
| AES-CCM | `aes_ccm.h` | CCM mode (authenticated counter mode). |
| AES-EAX | `aes_eax.h` | EAX authenticated encryption mode. |
| AES-GCM-SIV | `aes_gcm_siv.h` | Nonce-misuse resistant variant. |
| AES-OCB | `aes_ocb.h` | Offset Codebook Mode. |
| AES-SIV | `aes_siv.h` | Synthetic IV mode; double-key (SIV_encrypt takes `keys` not `key`). |
| ChaCha20-Poly1305 | `chacha20_poly1305.h` | Monocypher-based. `key[32]`, `nonce[...]`. |
| XChaCha20-Poly1305 | (via Monocypher) | Extended nonce (24 bytes) via `crypto_aead_init_x()`. |

Root API exposes: `nextssl_aead_aes_gcm_encrypt/decrypt()`. Internals available directly.

### 6.3 MAC — 3 primitives

**Path:** `src/modern/mac/`

| Algorithm | Notes |
|-----------|-------|
| HMAC | `hash_for_hmac(name)` + HMAC construction over any HASH_USAGE_HMAC hash. |
| Poly1305 | `aes_poly1305.h` — AES-keyed Poly1305 MAC. |
| KMAC-128/256 | Via hash registry; `hash_for_hmac("kmac128")`. |

HMAC exposed via root: `nextssl_mac_hmac_compute(algo, key, key_len, data, data_len, out, out_len)`.

### 6.4 KDF — 2 algorithms

**Path:** `src/modern/kdf/`

| Algorithm | Notes |
|-----------|-------|
| HKDF | RFC 5869. `hkdf_extract(salt, ikm)` → PRK; `hkdf_expand(prk, info, okm_len)`. Supported over any `HASH_USAGE_HKDF` hash. |
| PBKDF2 | RFC 2898. Over any `HASH_USAGE_PBKDF2` hash. |

Root: `nextssl_kdf_hkdf()`, `nextssl_kdf_pbkdf2()`.

### 6.5 Asymmetric / Curves — 8 algorithms (2 conditional)

**Path:** `src/modern/asymmetric/`, `src/modern/ed25519/`, `src/modern/curve_math/`

| Algorithm | Source | Notes |
|-----------|--------|-------|
| Ed25519 | `src/modern/ed25519/ed25519.h` | `ed25519_create_keypair`, `ed25519_sign`, `ed25519_verify`, `ed25519_key_exchange`, `ed25519_add_scalar`. |
| X25519 | Monocypher (`monocypher.h`) | `crypto_x25519_public_key`, `crypto_x25519`. ECDH over Curve25519. |
| EdDSA (Monocypher) | Monocypher | `crypto_eddsa_key_pair`, `crypto_eddsa_sign`, `crypto_eddsa_check`. (Ed25519 + BLAKE2b). |
| Ed448 | `src/modern/asymmetric/ed448.h` (wolfSSL shim) | 57-byte keys, 114-byte signatures. `#ifdef HAVE_ED448`. |
| Curve448 / X448 | `src/modern/asymmetric/curve448.h` (wolfSSL shim) | 56-byte keys. `#ifdef HAVE_CURVE448`. Deterministic keygen via `wc_curve448_make_key_deterministic`. |
| P-256 | `src/modern/asymmetric/` | NIST P-256 (secp256r1). |
| P-384 | `src/modern/asymmetric/` | NIST P-384 (secp384r1). |
| P-521 | `src/modern/asymmetric/` | NIST P-521 (secp521r1). |

Root: `nextssl_asym_ed25519_keypair/sign/verify()`, `nextssl_asym_x25519_exchange()`, `nextssl_asym_p256/p384/p521_*()`.

Also includes `src/modern/encoding/` — encoding utilities specific to modern crypto (distinct from `src/common/encoding/`).

---

## 7. Common Utilities

> **Encoding formats:** 7 (base16/32/58/64/64url/hex/ff70) + 1 radix-common utility | **Secure wipe backends:** 3 | **Sanitizer files:** 4

**Path:** `src/common/`

### 7.1 Encodings — 7 formats + 1 shared utility

**Path:** `src/common/encoding/`

| Module | File | Functionality |
|--------|------|---------------|
| Base16 | `base16.h` / `base16.c` | Hex encode/decode. Lowercase and uppercase variants (`radix_base16_encode`, `radix_base16_encode_upper`). |
| Base32 | `base32.h` / `base32.c` | RFC 4648 Base32. Alphabet: A-Z, 2-7. Padded to multiple of 8. Accepts upper/lowercase on decode. |
| Base58 | `base58.h` / `base58.c` | Bitcoin alphabet (no 0/O/I/l). No padding. Output buffer ≥ `input_len * 2 + 1`. |
| Base64 | `base64.h` / `base64.c` | RFC 4648 standard. +/ alphabet. Padded to multiple of 4. |
| Base64URL | `base64url.h` / `base64url.c` | RFC 4648 URL-safe. -_ alphabet. `encode_nopad` variant for JWT. Accepts padded/unpadded on decode. |
| Hex | `hex.h` / `hex.c` | Alias/shortcut for hex encoding. |
| FF70 | `ff70.h` / `ff70.c` | Custom framing format. `FF70DecodedFrame` struct. |
| Radix Common | `radix_common.h` / `radix_common.c` | Shared error codes and utilities for all radix encoders. |

### 7.2 Secure Memory — 3 platform backends (inline)

**File:** `src/common/secure_zero.h`

`secure_zero(buf, len)` — portable guaranteed secure wipe.
- Windows: `SecureZeroMemory()`
- C11 Annex K: `memset_s()`
- Fallback: volatile-pointer loop + compiler memory barrier.

Defined as `static inline` — no `.c` file needed.

**File:** `src/common/mem/secure_memory.h` — additional memory management utilities.

### 7.3 Input Sanitizer — 4 files

**Path:** `src/common/sanitizer/`  
**Files:** `nextssl_sanitizer.h/.c`, `nextssl_data.h`, `nextssl_errors.h`, `nss_shim.h`

Input validation layer for all public-facing API calls. Validates pointer non-null, size bounds, buffer alignment, and algorithm name whitelist checks.

---

## 8. File Map by Directory

```
src/
├── root/                       ← Public umbrella layer
│   ├── nextssl.h               ← Master include header
│   ├── nextssl_export.h        ← NEXTSSL_API macro
│   ├── hash/root_hash.h        ← Hash public API
│   ├── seed/root_seed.h        ← Seed public API
│   ├── modern/root_modern.h    ← Modern crypto public API
│   ├── pow/root_pow.h          ← PoW public API
│   └── pqc/root_pqc.h         ← PQC public API
│
├── hash/                       ← 41 hash algorithm implementations
│   ├── interface/              ← hash_ops.h (vtable), hash_registry.h/.c
│   ├── fast/                   ← sha224/256/384/512, sha512_224/256, sm3/
│   ├── blake/                  ← blake2b, blake2s, blake3 (+SIMD dispatch)
│   ├── sponge/                 ← sha3_224/256/384/512, keccak, shake, kmac
│   ├── sponge_xof/             ← SHAKE XOF base
│   ├── legacy/                 ← sha0/1, md2/4/5, nt, ripemd128/160/256/320, whirlpool, has160
│   ├── skein/                  ← skein256/512/1024 (Threefish based)
│   └── memory_hard/            ← argon2*, scrypt, yescrypt, bcrypt, catena, lyra2, makwa, pomelo, balloon/
│
├── seed/                       ← 3-tier seed derivation system
│   ├── random/                 ← TIER 1: entropy.h, seed_derive_random.h
│   ├── hash/                   ← TIER 2: seed_core.h, seed_types.h, ctr_mode.h, hash_registry.h
│   └── udbf/                   ← TIER 3: udbf.h, udbf_errors.h, rootkey.h
│
├── pow/                        ← Proof-of-Work system
│   ├── core/                   ← pow_types.h (challenge/solution/adapter structs)
│   ├── dhcm/                   ← dhcm_types.h (41-algo enum), dhcm_core.h, dhcm_difficulty.h, dhcm_math.h
│   ├── server/                 ← pow_challenge.h (generate), pow_verify.h (verify)
│   ├── client/                 ← pow_solver.h, pow_limits.h, pow_reject.h, pow_timer.h
│   ├── dispatcher.h/.c         ← Algorithm name → pow_adapter_t lookup
│   ├── pow_api.c               ← Unified PoW API (symbols exported via root_pow.h)
│   ├── fast/                   ← SHA-2 PoW adapters
│   ├── blake/                  ← BLAKE PoW adapters
│   ├── sponge/                 ← SHA-3/Keccak PoW adapters
│   ├── sponge_xof/             ← SHAKE PoW adapters
│   ├── skein/                  ← Skein PoW adapters
│   ├── legacy/                 ← Legacy hash PoW adapters
│   └── memory_hard/            ← Memory-hard PoW adapters
│
├── pqc/                        ← Post-Quantum Cryptography
│   ├── pqc_main.c              ← All algorithm wrappers; DRBG; domain separation
│   ├── interface_kem.h         ← Legacy Kyber interface
│   ├── interface_sign.h        ← Legacy Dilithium + SPHINCS+ interface
│   ├── common/                 ← hkdf/, randombytes.h
│   ├── kem/                    ← ml-kem-512/768/1024, hqc-128/192/256, mceliece* (10 variants)
│   └── sign/                   ← ml-dsa-44/65/87, falcon-512/1024/padded-512/padded-1024, sphincs+ (12 variants)
│
├── modern/                     ← Classical modern cryptography
│   ├── base_encryption.c
│   ├── symmetric/              ← AES-CBC, AES internals, ChaCha20
│   ├── aead/                   ← AES-GCM, AES-CCM, AES-EAX, AES-GCM-SIV, AES-OCB, AES-SIV, ChaCha20-Poly1305
│   ├── mac/                    ← HMAC, Poly1305, KMAC paths
│   ├── kdf/                    ← HKDF (RFC 5869), PBKDF2 (RFC 2898)
│   ├── asymmetric/             ← Ed448, Curve448, P-256/384/521, wolfSSL shims
│   ├── ed25519/                ← Ed25519 (standalone implementation)
│   ├── curve_math/             ← Shared curve arithmetic
│   └── encoding/               ← Encoding utilities for modern crypto layer
│
└── common/                     ← Shared utilities
    ├── secure_zero.h           ← Portable secure wipe (inline, no .c needed)
    ├── mem/secure_memory.h     ← Memory management
    ├── encoding/               ← base16/32/58/64/64url, hex, ff70, radix_common
    └── sanitizer/              ← Input validation: nextssl_sanitizer.h/.c, nextssl_data.h, nextssl_errors.h
```
