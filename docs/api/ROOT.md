# Root Interface

`root/nextssl_root.h` is the explicit-algorithm bypass layer.  It is
auto-included at the bottom of both `nextssl.h` and `nextssl_lite.h`.

**The include path itself is the warning.** If you write:

```c
#include "nextssl.h"
// then use nextssl_root_sha1(...) — you have deliberately opted out of
// the safe profile defaults.
```

---

## When to Use

| Use case | Appropriate? |
|---|---|
| Protocol implementor matching an external algorithm requirement | ✓ |
| Test harness verifying known-answer vectors for a specific algorithm | ✓ |
| Code that cannot accept the profile-selected default | ✓ |
| Normal application encryption / hashing | ✗ — use `nextssl_encrypt`, `nextssl_hash` |
| Any code that will run in production with user data | ✗ unless audited |

---

## Hash Functions

```c
// SHA-256: 32-byte output
int nextssl_root_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

// SHA-512: 64-byte output
int nextssl_root_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

// BLAKE3: variable-length output
int nextssl_root_blake3(const uint8_t *data, size_t len,
                        uint8_t *out, size_t out_len);

// SHA-1: 20-byte output — legacy, known weak, use only when required
int nextssl_root_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

// MD5: 16-byte output — legacy/alive, cryptographically broken for security
int nextssl_root_md5(const uint8_t *data, size_t len, uint8_t out[16]);
```

---

## AEAD Functions

**Output layout:** `[ciphertext][16-byte tag]` — the nonce is NOT prepended.
The caller owns the nonce and is responsible for uniqueness.

- `ct` buffer must be at least `plen + 16` bytes.
- `clen` for decrypt must equal `plaintext_bytes + 16`.
- Returns `-1` on authentication failure (decrypt).

```c
// AES-256-GCM
int nextssl_root_aes256gcm_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t *pt, size_t plen,
                                   uint8_t *ct);

int nextssl_root_aes256gcm_decrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t *ct, size_t clen,
                                   uint8_t *pt);

// ChaCha20-Poly1305 (same layout)
int nextssl_root_chacha20_encrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t *pt, size_t plen,
                                  uint8_t *ct);

int nextssl_root_chacha20_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t *ct, size_t clen,
                                  uint8_t *pt);
```

---

## Classical Key Operations

```c
// X25519 keypair: pk=32B, sk=32B
int nextssl_root_x25519_keygen(uint8_t pk[32], uint8_t sk[32]);

// X25519 scalar multiply: my_sk + their_pk → shared_secret (32B)
int nextssl_root_x25519_exchange(const uint8_t my_sk[32],
                                 const uint8_t their_pk[32],
                                 uint8_t ss[32]);

// Ed25519 keypair: pk=32B, sk=64B
int nextssl_root_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]);

// Ed25519 sign: sig=64B
int nextssl_root_ed25519_sign(uint8_t sig[64],
                               const uint8_t *msg, size_t mlen,
                               const uint8_t sk[64]);

// Ed25519 verify: returns 1 valid, 0 invalid
int nextssl_root_ed25519_verify(const uint8_t sig[64],
                                const uint8_t *msg, size_t mlen,
                                const uint8_t pk[32]);
```

---

## Post-Quantum — KEM (ML-KEM-768)

```c
// Keypair: pk=1184B, sk=2400B
int nextssl_root_mlkem768_keygen(uint8_t *pk, uint8_t *sk);

// Encapsulate: ct=1088B, ss=32B
int nextssl_root_mlkem768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);

// Decapsulate: ct=1088B → ss=32B
int nextssl_root_mlkem768_decaps(const uint8_t *ct, const uint8_t *sk,
                                 uint8_t ss[32]);
```

---

## Post-Quantum — Signatures

### ML-DSA-65

```c
// Keypair: pk=1952B, sk=4032B
int nextssl_root_mldsa65_keygen(uint8_t *pk, uint8_t *sk);

// Sign: sig up to 3309B, sets *sig_len
int nextssl_root_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t mlen,
                               const uint8_t *sk);

// Verify: returns 1 valid, 0 invalid
int nextssl_root_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                                const uint8_t *msg, size_t mlen,
                                const uint8_t *pk);
```

### ML-DSA-87

```c
// Keypair: pk=2592B, sk=4896B
int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk);

// Sign: sig up to 4627B, sets *sig_len
int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t mlen,
                               const uint8_t *sk);

// Verify: returns 1 valid, 0 invalid
int nextssl_root_mldsa87_verify(const uint8_t *sig, size_t sig_len,
                                const uint8_t *msg, size_t mlen,
                                const uint8_t *pk);
```
