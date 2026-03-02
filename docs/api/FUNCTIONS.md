# Function Reference

All public functions in both variants.

---

## Both Variants

These functions have identical signatures in full and lite.

| Function | Signature | Returns |
|---|---|---|
| `nextssl_version` | `(void)` | `const char*` |
| `nextssl_variant` | `(void)` | `const char*` — `"full"` or `"lite"` |
| `nextssl_security_level` | `(void)` | `const char*` |
| `nextssl_random` | `(uint8_t *out, size_t len)` | `int` |
| `nextssl_hash` | `(const uint8_t *data, size_t len, uint8_t hash[32])` | `int` |
| `nextssl_derive_key` | `(const uint8_t *in, size_t in_len, const char *ctx, uint8_t *out, size_t out_len)` | `int` |
| `nextssl_secure_zero` | `(void *data, size_t len)` | `void` |
| `nextssl_constant_compare` | `(const void *a, const void *b, size_t len)` | `int` — 1 equal, 0 not |
| `nextssl_init` | `(int profile)` | `int` |
| `nextssl_init_custom` | `(const nextssl_custom_profile_t *p)` | `int` |
| `nextssl_selftest` | `(void)` | `int` |
| `nextssl_cleanup` | `(void)` | `void` |

---

## Full Variant Only

### Encryption

```c
int nextssl_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);
```

Output: `[12-byte nonce][ciphertext][16-byte tag]` — allocate `plaintext_len + 28`.

```c
int nextssl_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);
```

### Password Hashing

```c
int nextssl_password_hash(
    const char *password, size_t password_len,
    char *hash_output, size_t hash_output_len);  // hash_output_len >= 128
```

```c
int nextssl_password_verify(
    const char *password, size_t password_len,
    const char *stored_hash);  // returns 1 match, 0 mismatch, <0 error
```

### Key Exchange (X25519)

```c
int nextssl_keyexchange_keypair(uint8_t public_key[32], uint8_t secret_key[32]);

int nextssl_keyexchange_compute(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]);
```

### Signatures (Ed25519)

```c
int nextssl_sign_keypair(uint8_t public_key[32], uint8_t secret_key[64]);

int nextssl_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64]);

int nextssl_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32]);  // returns 1 valid, 0 invalid
```

### Post-Quantum KEM (ML-KEM-768)

```c
int nextssl_pq_kem_keypair(uint8_t *public_key, uint8_t *secret_key);
// public_key: 1184 B   secret_key: 2400 B

int nextssl_pq_kem_encapsulate(
    uint8_t *ciphertext,          // 1088 B
    uint8_t *shared_secret,       // 32 B
    const uint8_t *public_key);

int nextssl_pq_kem_decapsulate(
    uint8_t *shared_secret,       // 32 B
    const uint8_t *ciphertext,    // 1088 B
    const uint8_t *secret_key);   // 2400 B
```

### Post-Quantum Signatures (ML-DSA-65)

```c
int nextssl_pq_sign_keypair(uint8_t *public_key, uint8_t *secret_key);
// public_key: 1952 B   secret_key: 4000 B

int nextssl_pq_sign(
    uint8_t *signature, size_t *signature_len,  // sig up to 3293 B
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

int nextssl_pq_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);  // returns 1 valid, 0 invalid
```

---

## Lite Variant — Signature Differences

### Encryption (explicit nonce)

```c
int nextssl_encrypt(
    const uint8_t *key,       // 32 B
    const uint8_t *nonce,     // 12 B — caller supplies, must be unique per key
    const uint8_t *plaintext, size_t plen,
    uint8_t *ciphertext);     // allocate plen + 16 (tag only, no nonce prepended)

int nextssl_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext, size_t clen,
    uint8_t *plaintext);
```

### Password Hashing (explicit salt)

```c
int nextssl_password_hash(
    const uint8_t *password, size_t plen,
    const uint8_t *salt,      // 16 B — caller supplies
    uint8_t *output);         // 32 B hash

int nextssl_password_verify(
    const uint8_t *password, size_t plen,
    const uint8_t *salt,
    const uint8_t *expected_hash);
```

### Unified Key Exchange / Signatures (pqc flag)

```c
// Key exchange
int nextssl_keygen(uint8_t *public_key, uint8_t *secret_key, int pqc);
// pqc=0: pk=32B sk=32B (X25519)   pqc=1: pk=1568B sk=3168B (ML-KEM-1024)

int nextssl_keyexchange(
    const uint8_t *my_secret, const uint8_t *their_public,
    uint8_t *shared_secret, uint8_t *ciphertext, int pqc);

int nextssl_keyexchange_decaps(
    const uint8_t *ciphertext, const uint8_t *my_secret,
    uint8_t *shared_secret);   // PQC only

// Signatures
int nextssl_sign_keygen(uint8_t *public_key, uint8_t *secret_key, int pqc);
// pqc=0: pk=32B sk=64B (Ed25519)  pqc=1: pk=2592B sk=4864B (ML-DSA-87)

int nextssl_sign(
    const uint8_t *message, size_t mlen,
    const uint8_t *secret_key,
    uint8_t *signature,        // 64 B Ed25519 / 4627 B ML-DSA-87
    int pqc);

int nextssl_verify(
    const uint8_t *message, size_t mlen,
    const uint8_t *signature,
    const uint8_t *public_key,
    int pqc);
```

### Lite-Only Discovery Functions

```c
int nextssl_has_algorithm(const char *algorithm);   // 1 available, 0 not
int nextssl_list_algorithms(char *buffer, size_t size);  // returns count (9)
```

---

## Radix Encoding API

> **vNEXT** — The radix encoding API (`nextssl_base64_*`, `nextssl_base58_*`,
> etc.) is not yet exposed at Layer 4.  `src/utils/radix/base64.c` is used
> internally by the PoW subsystem.  A stable public API is planned for a
> future release.
