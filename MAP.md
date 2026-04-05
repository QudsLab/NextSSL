# MAP.md — NextSSL Agent Navigation Map

> Compact descriptor for AI agents. Each section identifies the subsystem, its entry point,
> key types/functions, and what files to read for implementation detail.
> Read SOURCE.md for full documentation.

---

## LIBRARY ENTRY POINT

```
#include "src/root/nextssl.h"   ← the ONLY header external consumers need
NEXTSSL_API macro               ← from src/root/nextssl_export.h
```

---

## SUBSYSTEM SUMMARY

| Subsystem | Count | Public Header | Core Implementation |
|-----------|-------|--------------|---------------------|
| Hash | **41 algos** (+ up to 3 optional) | `root/hash/root_hash.h` | `hash/interface/hash_registry.c` |
| Seed | **3 tiers**, 41 engine choices | `root/seed/root_seed.h` | `seed/hash/seed_core.c` |
| PoW | **41 eligible algos**, 7 adapter dirs | `root/pow/root_pow.h` | `pow/pow_api.c`, `pow/dispatcher.c` |
| PQC | **35 variants** (16 KEM + 19 sign) | `root/pqc/root_pqc.h` | `pqc/pqc_main.c` |
| Modern | **8 AEAD**, 2 sym, 3 MAC, 2 KDF, **8 asym** | `root/modern/root_modern.h` | `modern/symmetric/`, `modern/aead/`, `modern/kdf/`, `modern/asymmetric/` |
| Common | **7 encodings**, 3 wipe backends | `common/secure_zero.h`, `common/encoding/` | inline / .c files |

---

## HASH SUBSYSTEM — 41 algorithms (+ up to 3 optional)

> **Registry capacity:** 64 | **Context buffer:** 2048 bytes | **Purpose accessors:** 5 | **Usage flag bits:** 5  
Every algorithm is a `hash_ops_t` vtable: `name`, `digest_size`, `block_size`, `usage_flags`, `init/update/final`, `wu_per_eval`, `mu_per_eval`, `parallelism`.

**Working with hashes:**
1. `hash_registry_init()` — call once at startup
2. `hash_lookup("sha256")` → `const hash_ops_t*` — by name lookup
3. `hash_for_hmac/pbkdf2/hkdf/pow/seed("name")` — purpose-typed lookups (checks flag)
4. Allocate `uint8_t ctx[HASH_OPS_CTX_MAX]` (2048 bytes) on caller stack
5. Call `ops->init(ctx)`, `ops->update(ctx, data, len)`, `ops->final(ctx, out)`

**One-shot API:** `nextssl_hash_compute(algo, data, len, out, &out_len)` — top-level.

### Registered Algorithms — 41 core total (+ up to 3 optional)

> 6 SHA-2 + 3 BLAKE + 5 SHA-3/Keccak + 2 XOF + 2 KMAC + 8 MemHard + 12 Legacy + 3 Skein = **41**  
> Optional: + SM3 (`NEXTSSL_HAS_GMSSL`) + Pomelo (`NEXTSSL_HAS_POMELO`) + Makwa (`NEXTSSL_HAS_MAKWA`) + Balloon (`NEXTSSL_HAS_BALLOON`)

**Fast SHA-2 (6):** `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`, `sha512-256`  
→ `src/hash/fast/` — all `HASH_USAGE_ALL`

**BLAKE (3):** `blake2b` (64B), `blake2s` (32B), `blake3` (32B)  
→ `src/hash/blake/` — BLAKE3 has SIMD dispatch (AVX2/AVX512/SSE2/SSE4.1) — all `HASH_USAGE_ALL`

**SHA-3 / Keccak (5):** `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `keccak256`  
→ `src/hash/sponge/` — all `HASH_USAGE_ALL`; Keccak256 uses `0x01` domain byte (not `0x06`)

**XOF (2):** `shake128` (32B fixed), `shake256` (64B fixed)  
→ `src/hash/sponge_xof/` — `HASH_USAGE_POW | HASH_USAGE_SEED` only (not HMAC/PBKDF2/HKDF)

**KMAC (2):** `kmac128` (32B), `kmac256` (64B)  
→ `src/hash/sponge/sp800_185/kmac.h` — `HASH_USAGE_HMAC | HASH_USAGE_POW | HASH_USAGE_SEED`

**Memory-Hard KDF adapters (8):** `argon2id`, `argon2i`, `argon2d`, `scrypt`, `yescrypt`, `catena`, `lyra2`, `bcrypt`  
→ `src/hash/memory_hard/` — `HASH_USAGE_POW | HASH_USAGE_SEED` only  
→ Accumulator pattern: collects all `update()` data in `buf[2040]`, calls full KDF on `final()`  
→ Fixed params: t=2, m=65536 KiB, threads=1, salt=16×0x00  
→ Optional: `pomelo` (`NEXTSSL_HAS_POMELO`), `makwa` (`NEXTSSL_HAS_MAKWA`)

**Skein (3):** `skein256`, `skein512`, `skein1024`  
→ `src/hash/skein/` — Threefish-based — all `HASH_USAGE_ALL`

**Legacy / Weak ⚠️ (12):** `sha1`, `sha0`, `md5`, `md4`, `md2`, `nt`, `ripemd128`, `ripemd160`, `ripemd256`, `ripemd320`, `whirlpool`, `has160`  
→ `src/hash/legacy/` — `sha1` / RIPEMD: `HASH_USAGE_ALL`; others limited  
→ `nt`: no native streaming API — accumulator adapter only; input must be raw UTF-16LE bytes

**National Standard (1, conditional):** `sm3`  
→ `src/hash/fast/sm3/` — `#ifdef NEXTSSL_HAS_GMSSL` — `HASH_USAGE_ALL`

**Usage flag constants:** `HASH_USAGE_HMAC(0)`, `HASH_USAGE_PBKDF2(1)`, `HASH_USAGE_HKDF(2)`, `HASH_USAGE_POW(3)`, `HASH_USAGE_SEED(4)`, `HASH_USAGE_ALL_KDF`, `HASH_USAGE_ALL`

---

## SEED SUBSYSTEM — 3 Tiers | 41 engine choices | 8 categories | 4 UDBF errors

**Entry:** `src/root/seed/root_seed.h`

```
TIER 1 → seed_derive_random(out, len)          → OS RNG (BCryptGenRandom / getrandom / arc4random_buf)
TIER 2 → seed_hash_derive(cfg, seed, len, out) → CTR-mode: Hash(seed||label||counter)
TIER 3 → UDBF                                  → test-mode KAT vector injection (overrides TIER 2)
```

**TIER 2 config:** `seed_hash_config_t { engine: const hash_ops_t*, ctx_label: const char* }`  
- engine=NULL → defaults to SHA-512  
- Results fully deterministic: same seed + label → same output  
- Max output: 1 MB; counter starts at 1, 4-byte big-endian

**TIER 3 UDBF:**  
- `udbf_feed(data, len)` — load binary format: `[uint32_le:total][entries: uint8:labellen|label|uint32_le:valuelen|value]`  
- `udbf_read(label, out, olen)` — retrieve by label  
- `seed_udbf_is_active()` — checked by seed_core before CTR expansion  
- `udbf_wipe()` — secure clear; allows reload  
- Error: `UDBF_OK=0`, `UDBF_ERR_ALREADY_LOADED=-1`, `UDBF_ERR_NO_DATA=-2`, `UDBF_ERR_LABEL_NOT_FOUND=-3`, `UDBF_ERR_TOO_LARGE=-4`

**Rootkey:** `rootkey_get(ROOTKEY_MODE_SEED, label, coins, coins_len, out, out_len)` — HKDF domain separation. Used by PQC DRBG.

**Seed hash registry:** `hash_lookup_by_name(name)` in `src/seed/hash/hash_registry.h` — same 41 algos as main registry, **8 categories** (BLAKE=0, Fast=1, Legacy=2, MemHard=3, Sponge=4, XOF=5, Skein=6, KMAC=7).

---

## POW SUBSYSTEM — 41 eligible algorithms | 7 adapter dirs | 3 difficulty models

**Entry:** `src/root/pow/root_pow.h`  
**Implementation:** `src/pow/pow_api.c` (symbols), `src/pow/dispatcher.c` (routing)

### Key Types — 3 structs (all in `src/pow/core/pow_types.h`)

**`pow_challenge_t`:** `version`, `challenge_id[16]`, `algorithm_id[32]` (hyphen-form), `context[256]`, `target[64]`, `difficulty_bits`, `wu`, `mu`, `expires_unix`

**`pow_solution_t`:** `challenge_id[16]`, `nonce` (uint64), `hash_output[64]`, `solve_time_seconds`, `attempts`

**`pow_adapter_t`:** `name`, `hash(input, len, params, out)`, `get_cost(difficulty_bits, DHCMResult*)`

### Server API — 2 calls
- `nextssl_pow_server_generate_challenge(config, algo, context, ctx_len, bits, out)` → fills `wu`/`mu` via DHCM
- `nextssl_pow_server_verify_solution(challenge, solution, &out_valid)` → re-hashes, checks target + expiry

### Client API — 4 calls
- `nextssl_pow_client_parse_challenge(b64_str, out)` → decode base64-JSON
- `nextssl_pow_client_solve(challenge, out)` → brute-force: `hash(context || decimal_nonce)`
- Nonce normalisation: `pow_algo_name_normalise(name)` — underscores → hyphens

### DHCM (Dynamic Hash Cost Model) — `src/pow/dhcm/` — 41 algo enum, 3 models, 7 output fields

41 algorithms in `DHCMAlgorithm` enum (grouped by high byte: 0x01=SHA-2 **[6]**, 0x02=BLAKE **[3]**, 0x03=SHA3/KMAC **[7]**, 0x04=XOF **[2]**, 0x05=MemHard **[8]**, 0x06=Skein **[3]**, 0x07=Legacy **[12]**).

**Difficulty models:** `TARGET_BASED` → E[N]=2^bits | `ITERATION_BASED` → cost in params | `NONE` → verify-only

**`dhcm_core_calculate(params, result)`** → fills `work_units_per_eval`, `memory_units_per_eval`, `expected_trials`, `total_work_units`, `total_memory_units`, `verification_work_units`, cost_model_version="2.0.0"

---

## PQC SUBSYSTEM — 35 variants (16 KEM + 19 sign) across 6 families

**Entry:** `src/root/pqc/root_pqc.h`  
**Implementation:** `src/pqc/pqc_main.c`  
**Compile guards:** `ENABLE_ML_KEM`, `ENABLE_ML_DSA`, `ENABLE_FALCON`, `ENABLE_HQC`, `ENABLE_MCELIECE`, `ENABLE_SPHINCS`

### KEM Algorithms — 16 variants (3 + 3 + 10)

| Family | Variant count | Variants | Paths | Guard |
|--------|--------------|----------|-------|-------|
| ML-KEM (Kyber) | **3** | 512, 768, 1024 | `pqc/kem/ml-kem-{512,768,1024}/ref/` | `ENABLE_ML_KEM` |
| HQC | **3** | 128, 192, 256 | `pqc/kem/hqc-{128,192,256}/ref/` | `ENABLE_HQC` |
| Classic McEliece | **10** | 348864(f), 460896(f), 6688128(f), 6960119(f), 8192128(f) | `pqc/kem/mceliece*/ref/` | `ENABLE_MCELIECE` |

Each KEM: `pqc_{algo}_keypair`, `pqc_{algo}_keypair_derand`, `pqc_{algo}_encaps`, `pqc_{algo}_encaps_derand`, `pqc_{algo}_decaps`

### Signature Algorithms — 19 variants (3 + 4 + 12)

| Family | Variant count | Variants | Paths | Guard |
|--------|--------------|----------|-------|-------|
| ML-DSA (Dilithium) | **3** | 44, 65, 87 | `pqc/sign/ml-dsa-{44,65,87}/ref/` | `ENABLE_ML_DSA` |
| Falcon | **4** | 512, 1024, padded-512, padded-1024 | `pqc/sign/falcon-{512,1024,padded-512,padded-1024}/ref/` | `ENABLE_FALCON` |
| SPHINCS+ | **12** | sha2/shake × 128/192/256 × f/s × simple = 12 | `pqc/sign/sphincs-{sha2,shake}-{128,192,256}{f,s}-simple/ref/` | `ENABLE_SPHINCS` |

Each sign algo: `pqc_{algo}_keypair`, `pqc_{algo}_keypair_derand`, `pqc_{algo}_sign`, `pqc_{algo}_sign_derand`, `pqc_{algo}_verify`

### DRBG & Domain Separation

```
pqc_seed_from_coins(label, coins, 32)
  → rootkey_get(ROOTKEY_MODE_SEED, label, coins, 32, seed_buf, 32)   ← HKDF
  → pqc_randombytes_seed(seed_buf, 32)
  → wipe seed_buf
```

All `_derand` variants use `pqc_seed_from_coins` to ensure cross-algorithm independence.

Public: `pqc_drbg_seed(seed,salt,info)`, `pqc_drbg_reseed(seed,salt)`, `pqc_udbf_feed(buf,len)`, `pqc_randombytes(out,len)`

---

## MODERN CRYPTO SUBSYSTEM — 8 AEAD | 2 sym | 3 MAC | 2 KDF | 8 asym

**Entry:** `src/root/modern/root_modern.h`

### Symmetric
- AES-CBC: `nextssl_sym_aes_cbc_encrypt/decrypt(key, key_len[16/24/32], iv[16], in, len, out)`
- ChaCha20: via Monocypher `src/modern/symmetric/`

### AEAD modes — 8 (`src/modern/aead/`)
`AES-GCM`, `AES-CCM`, `AES-EAX`, `AES-GCM-SIV`, `AES-OCB`, `AES-SIV`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305`  
Root API: `nextssl_aead_aes_gcm_encrypt/decrypt(key, key_len, nonce[12], aad, aad_len, in, len, out)`

### MAC — 3 primitives (`src/modern/mac/`)
- HMAC: over any `HASH_USAGE_HMAC` algorithm via `hash_for_hmac(name)`
- Poly1305: `src/modern/aead/aes_poly1305.h`

### KDF — 2 algorithms (`src/modern/kdf/`)
- HKDF (RFC 5869): `hkdf_extract(salt, ikm) → PRK` + `hkdf_expand(prk, info, okm_len)`
- PBKDF2 (RFC 2898): over any `HASH_USAGE_PBKDF2` algorithm

### Asymmetric — 8 algorithms, 2 conditional (`src/modern/asymmetric/`, `src/modern/ed25519/`)
- **Ed25519:** `ed25519_create_keypair/sign/verify/key_exchange/add_scalar`
- **X25519 (Monocypher):** `crypto_x25519_public_key`, `crypto_x25519`
- **EdDSA (Monocypher):** Ed25519 + BLAKE2b — `crypto_eddsa_key_pair/sign/check`
- **Ed448:** 57-byte keys, 114-byte sigs — `#ifdef HAVE_ED448`
- **Curve448 / X448:** 56-byte keys — `#ifdef HAVE_CURVE448` — wolfSSL shim
- **P-256, P-384, P-521:** NIST curves via `src/modern/asymmetric/`

---

## COMMON UTILITIES — 7 encodings | 3 wipe backends | 4 sanitizer files

### Secure Wipe — 3 platform backends
`secure_zero(buf, len)` — `src/common/secure_zero.h` — inline, no .c needed.  
Platform dispatch: `SecureZeroMemory` / `memset_s` / volatile loop + barrier.

### Encodings — 7 formats (`src/common/encoding/`)
| Encoder | Function prefix | Notes |
|---------|----------------|-------|
| Hex/Base16 | `radix_base16_*` | lower + upper variants |
| Base32 | `radix_base32_*` | RFC 4648; A-Z 2-7 |
| Base58 | `radix_base58_*` | Bitcoin alphabet; no padding |
| Base64 | `radix_base64_*` | RFC 4648; +/ padded |
| Base64URL | `radix_base64url_*` | -_ padded/unpadded |
| FF70 | `ff70_*` | Custom binary framing |

All return `RADIX_SUCCESS` or error code (from `radix_common.h`).

### Input Sanitizer (`src/common/sanitizer/`)
`nextssl_sanitizer.h` / `nextssl_sanitizer.c` — validates API inputs at system boundary.  
`nextssl_data.h` — validated data type wrappers.  
`nextssl_errors.h` — error code definitions.

---

## NAMING CONVENTIONS

- Algorithm names: **lowercase with hyphens** — `"sha3-256"`, `"blake3"`, `"argon2id"`, `"sha512-256"`
- `pow_algo_name_normalise()` converts underscores to hyphens automatically
- PQC function names: `pqc_{family}{variant}_{operation}` — e.g. `pqc_mlkem768_keypair`
- Root API: `nextssl_{subsystem}_{algo}_{operation}` — e.g. `nextssl_aead_aes_gcm_encrypt`

---

## CROSS-SUBSYSTEM DATA FLOW

```
OS Entropy ──→ seed_derive_random()
                     │
                     ▼
Seed Material ──→ seed_hash_derive(cfg)  [TIER 2: CTR-mode with any of 41 hashes]
                     │  [TIER 3 check: UDBF overrides if active]
                     ▼
Derived Key ──→ PQC DRBG (via rootkey_get HKDF domain separation)
             ──→ PoW challenge context
             ──→ KDF (HKDF/PBKDF2) input

Hash Registry ──→ PoW Dispatcher (adapter.hash calls hash_lookup)
              ──→ DHCM cost oracle (by DHCMAlgorithm enum, not registry)
              ──→ seed_hash_derive engine parameter

PoW Challenge ──→ Server: generate (DHCM fills wu/mu)
              ──→ Client: parse → solve (brute force nonce) → encode solution
              ──→ Server: verify (re-hash + target check + expiry check)
```

---

## QUICK REFERENCE: WHAT GOES WHERE

| Task | Count/Size | Where to look |
|------|-----------|--------------|
| Hash a buffer with any algorithm | 41 choices | `root_hash.h` → `nextssl_hash_compute()` |
| Get a hash algorithm by name | 41 registered | `hash/interface/hash_registry.h` → `hash_lookup()` |
| Check what algorithms support HMAC | ~29 of 41 | `hash_for_hmac(name)` → non-null means yes |
| Generate random seeds | 3 OS backends | `seed/random/seed_derive_random.h` |
| Deterministic key expansion | 41 engine choices | `seed/hash/seed_core.h` → `seed_hash_derive()` |
| Inject KAT test vectors | 4 error codes | `seed/udbf/udbf.h` → `udbf_feed()` |
| Domain-separated seed for PQC | 1 mode | `seed/udbf/rootkey.h` → `rootkey_get()` |
| Issue PoW challenge (server) | 41 eligible algos | `pow/server/pow_challenge.h` |
| Solve PoW challenge (client) | 4 error returns | `pow/client/pow_solver.h` |
| Get WU/MU cost for a hash | 41 algo enum, 7 result fields | `pow/dhcm/dhcm_core.h` → `dhcm_core_calculate()` |
| Lattice-based KEM/sign keygen | 16 KEM + 19 sign variants | `pqc/pqc_main.c` function table |
| Hash-based signature (stateless) | 12 SPHINCS+ variants | `pqc/sign/sphincs-*/` via `pqc_sphincs*_keypair/sign/verify` |
| AES-GCM encrypt | 3 key sizes (128/192/256) | `root_modern.h` → `nextssl_aead_aes_gcm_encrypt()` |
| HKDF key derivation | any of ~29 HASH_USAGE_HKDF algos | `modern/kdf/` → `hkdf_extract/expand()` |
| ECDH exchange | Curve25519 / X448 | `modern/asymmetric/` → `crypto_x25519()` (Monocypher) |
| Encode bytes as base64 | 6 encoding formats | `common/encoding/base64.h` → `radix_base64_encode()` |
| Secure memory wipe | 3 platform backends | `common/secure_zero.h` → `secure_zero()` |
| Validate API inputs | 4 sanitizer files | `common/sanitizer/nextssl_sanitizer.h` |
