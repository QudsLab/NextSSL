# Profiles and Configuration

---

## Security Profiles

Pass the profile index to `nextssl_init(profile)`.

| Index | Name | Default algorithms | Full | Lite |
|---|---|---|---|---|
| 0 | `MODERN` | SHA-256, AES-256-GCM, HKDF, Ed25519, X25519 | ✓ | ✓ |
| 1 | `COMPLIANCE` | FIPS/NIST aligned subset | ✓ | ✓ |
| 2 | `PQC` | BLAKE3, ML-KEM-1024, ML-DSA-87 | ✓ | ✓ |
| 3 | `COMPATIBILITY` | Includes legacy-alive algorithms | ✓ | — |
| 4 | `EMBEDDED` | ChaCha20-Poly1305, small footprint | ✓ | — |
| 5 | `RESEARCH` | All algorithms including legacy-unsafe | ✓ | — |

---

## Algorithm Enums

These enums are defined in `src/config/config.h`.  The Lite column shows
the maximum accepted ID in the lite variant.

### `nextssl_hash_algo_t`

| Value | Constant | Algorithm | Lite |
|---|---|---|---|
| 0 | `NEXTSSL_HASH_SHA256` | SHA-256 | ✓ |
| 1 | `NEXTSSL_HASH_SHA512` | SHA-512 | ✓ |
| 2 | `NEXTSSL_HASH_BLAKE3` | BLAKE3 | ✓ |
| 3 | `NEXTSSL_HASH_SHA384` | SHA-384 | — |
| 4 | `NEXTSSL_HASH_SHA1` | SHA-1 (legacy-alive) | — |
| 5 | `NEXTSSL_HASH_MD5` | MD5 (legacy-alive) | — |
| 6 | `NEXTSSL_HASH_BLAKE2B` | BLAKE2b | — |
| 7 | `NEXTSSL_HASH_SHA3_256` | SHA3-256 | — |
| 8 | `NEXTSSL_HASH_SHA3_512` | SHA3-512 | — |
| 9 | `NEXTSSL_HASH_BLAKE2S` | BLAKE2s | — |

### `nextssl_aead_algo_t`

| Value | Constant | Algorithm | Lite |
|---|---|---|---|
| 0 | `NEXTSSL_AEAD_AES_256_GCM` | AES-256-GCM | ✓ |
| 1 | `NEXTSSL_AEAD_CHACHA20_POLY1305` | ChaCha20-Poly1305 | ✓ |
| 2 | `NEXTSSL_AEAD_AES_128_GCM` | AES-128-GCM | — |
| 3 | `NEXTSSL_AEAD_AES_256_CCM` | AES-256-CCM | — |
| 5 | `NEXTSSL_AEAD_AEGIS256` | AEGIS-256 | — |
| 6 | `NEXTSSL_AEAD_XCHACHA20_POLY1305` | XChaCha20-Poly1305 | — |

### `nextssl_kdf_algo_t`

| Value | Constant | Algorithm | Lite |
|---|---|---|---|
| 0 | `NEXTSSL_KDF_HKDF_SHA256` | HKDF-SHA256 | ✓ |
| 1 | `NEXTSSL_KDF_ARGON2ID` | Argon2id | ✓ |
| 2 | `NEXTSSL_KDF_HKDF_SHA512` | HKDF-SHA512 | — |
| 3 | `NEXTSSL_KDF_ARGON2I` | Argon2i | — |
| 5 | `NEXTSSL_KDF_SCRYPT` | scrypt | — |
| 6 | `NEXTSSL_KDF_PBKDF2` | PBKDF2 | — |

### `nextssl_sign_algo_t`

| Value | Constant | Algorithm | Lite |
|---|---|---|---|
| 0 | `NEXTSSL_SIGN_ED25519` | Ed25519 | ✓ |
| 1 | `NEXTSSL_SIGN_ML_DSA_87` | ML-DSA-87 (Dilithium5) | ✓ |
| 3 | `NEXTSSL_SIGN_ML_DSA_65` | ML-DSA-65 (Dilithium3) | — |
| 4 | `NEXTSSL_SIGN_ML_DSA_44` | ML-DSA-44 (Dilithium2) | — |
| 8 | `NEXTSSL_SIGN_ECDSA_P256` | ECDSA P-256 | — |
| 10 | `NEXTSSL_SIGN_RSA_3072_PSS` | RSA-3072-PSS | — |

### `nextssl_kem_algo_t`

| Value | Constant | Algorithm | Lite |
|---|---|---|---|
| 0 | `NEXTSSL_KEM_X25519` | X25519 | ✓ |
| 1 | `NEXTSSL_KEM_ML_KEM_1024` | ML-KEM-1024 (Kyber1024) | ✓ |
| 3 | `NEXTSSL_KEM_ML_KEM_768` | ML-KEM-768 (Kyber768) | — |
| 4 | `NEXTSSL_KEM_ML_KEM_512` | ML-KEM-512 (Kyber512) | — |
| 7 | `NEXTSSL_KEM_ECDH_P256` | ECDH P-256 | — |
| 8 | `NEXTSSL_KEM_ECDH_P384` | ECDH P-384 | — |

---

## `nextssl_config_t` Struct

Internal config structure (read via `nextssl_config_get()`).

| Field | Type | Description |
|---|---|---|
| `profile` | `int` | Active profile index (0–5) |
| `default_hash` | `nextssl_hash_algo_t` | Default hash algorithm |
| `default_aead` | `nextssl_aead_algo_t` | Default AEAD algorithm |
| `default_kdf` | `nextssl_kdf_algo_t` | Default KDF |
| `default_sign` | `nextssl_sign_algo_t` | Default signature algorithm |
| `default_kem` | `nextssl_kem_algo_t` | Default KEM |
| `strict_mode` | `int` | Reject all algorithms outside profile |
| `allow_legacy` | `int` | Allow legacy-alive algorithms |
| `pqc_only` | `int` | Reject classical-only algorithms |
| `initialized` | `int` | 1 after successful `nextssl_init` |
| `profile_name` | `const char*` | Human-readable profile name |

---

## `nextssl_custom_profile_t` Struct

Passed to `nextssl_init_custom()`.  Use the typed enum fields — do not use
raw `int` values when initialising this struct.

```c
typedef struct {
    int hash;          // nextssl_hash_algo_t value
    int aead;          // nextssl_aead_algo_t value
    int kdf;           // nextssl_kdf_algo_t value
    int sign;          // nextssl_sign_algo_t value
    int kem;           // nextssl_kem_algo_t value
    const char *name;  // Optional label (NULL = "Custom")
} nextssl_custom_profile_t;
```

Example:

```c
nextssl_custom_profile_t prof = {
    .hash = NEXTSSL_HASH_ID_BLAKE3,
    .aead = NEXTSSL_AEAD_ID_CHACHA20POLY1305,
    .kdf  = NEXTSSL_KDF_ID_ARGON2ID,
    .sign = NEXTSSL_SIGN_ID_ED25519,
    .kem  = NEXTSSL_KEM_ID_X25519,
    .name = "MyProfile"
};
nextssl_init_custom(&prof);
```

The lite variant rejects any ID not compiled into that build.

---

## Configuration API

Nine functions, all prefixed `nextssl_config_`:

| Function | Description |
|---|---|
| `nextssl_config_init(int profile)` | Initialise config with a named profile |
| `nextssl_config_get(void)` | Return pointer to active config |
| `nextssl_config_algo_available(int category, int id)` | Check if an algorithm ID is compiled in |
| `nextssl_config_security_level(void)` | Return active security level string |
| `nextssl_config_profile_name(void)` | Return active profile name string |
| `nextssl_config_validate_algo(int category, int id)` | Validate ID against active profile rules |
| `nextssl_config_get_or_default(int category, int id)` | Return id if available, else profile default |
| `nextssl_config_reset(void)` | Reset to uninitialised state |
| `nextssl_config_init_custom(const nextssl_custom_profile_t *p)` | Initialise with custom profile |

---

## Error Codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `NEXTSSL_SUCCESS` | Success |
| -1 | `NEXTSSL_ERR_NOT_INIT` | Called before `nextssl_init` |
| -2 | `NEXTSSL_ERR_ALREADY_INIT` | `nextssl_init` called twice |
| -3 | `NEXTSSL_ERR_INVALID_PROF` | Unknown or out-of-range profile index |
| -4 | `NEXTSSL_ERR_ALGO_UNAVAIL` | Algorithm not compiled into this variant |
| -5 | `NEXTSSL_ERR_ALGO_BLOCKED` | Algorithm blocked by active profile |
