/**
 * @file root/nextssl_root.h
 * @brief NextSSL Full — Explicit-Algorithm (Root) Interface
 *
 * Including this header signals that you are operating OUTSIDE the safe
 * default path.  Every function here bypasses the active profile entirely —
 * the algorithm is hardcoded in the function name.
 *
 * Who should use this:
 *   - Protocol implementors that must match an external algorithm requirement
 *   - Test harnesses verifying known-answer vectors for specific algorithms
 *   - Any code that cannot accept the profile-selected default
 *
 * Who should NOT use this for normal application code:
 *   - Use nextssl_hash(), nextssl_encrypt(), etc. (the profile-driven defaults)
 *
 * Usage:
 *   #include "nextssl.h"               // safe defaults
 *   #include "root/nextssl_root.h"     // explicit algorithms — path is the warning
 *
 * Full variant: MD5, SHA-1, legacy AEAD, ML-KEM-768, ML-DSA-65/87 available.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_FULL_ROOT_H
#define NEXTSSL_FULL_ROOT_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../config.h"  /* NEXTSSL_API, platform detection */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Hash — Explicit Algorithm
 * ========================================================================== */

/** SHA-256: 32-byte output. */
NEXTSSL_API int nextssl_root_sha256(const uint8_t *data, size_t len,
                                    uint8_t out[32]);

/** SHA-512: 64-byte output. */
NEXTSSL_API int nextssl_root_sha512(const uint8_t *data, size_t len,
                                    uint8_t out[64]);

/** BLAKE3: variable output length. */
NEXTSSL_API int nextssl_root_blake3(const uint8_t *data, size_t len,
                                    uint8_t *out, size_t out_len);

/** SHA-1: 20-byte output. Legacy — known weak, use only when required. */
NEXTSSL_API int nextssl_root_sha1(const uint8_t *data, size_t len,
                                  uint8_t out[20]);

/** MD5: 16-byte output. Legacy/alive — cryptographically broken for security. */
NEXTSSL_API int nextssl_root_md5(const uint8_t *data, size_t len,
                                 uint8_t out[16]);

/* ==========================================================================
 * AEAD — Explicit Algorithm, Caller Supplies Nonce
 *
 * Output layout:  [ciphertext][16-byte tag]   (No prepended nonce.)
 * ct buffer must be at least  plen + 16  bytes.
 * clen for decrypt must be  plaintext_bytes + 16.
 * ========================================================================== */

NEXTSSL_API int nextssl_root_aes256gcm_encrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t *pt, size_t plen,
                                               uint8_t *ct);

NEXTSSL_API int nextssl_root_aes256gcm_decrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t *ct, size_t clen,
                                               uint8_t *pt);

NEXTSSL_API int nextssl_root_chacha20_encrypt(const uint8_t key[32],
                                              const uint8_t nonce[12],
                                              const uint8_t *pt, size_t plen,
                                              uint8_t *ct);

NEXTSSL_API int nextssl_root_chacha20_decrypt(const uint8_t key[32],
                                              const uint8_t nonce[12],
                                              const uint8_t *ct, size_t clen,
                                              uint8_t *pt);

/* ==========================================================================
 * Classical Key Operations
 * ========================================================================== */

/** X25519 keypair: pk=32B, sk=32B */
NEXTSSL_API int nextssl_root_x25519_keygen(uint8_t pk[32], uint8_t sk[32]);

/** X25519 scalar multiply: my_sk + their_pk → ss (32B) */
NEXTSSL_API int nextssl_root_x25519_exchange(const uint8_t my_sk[32],
                                             const uint8_t their_pk[32],
                                             uint8_t ss[32]);

/** Ed25519 keypair: pk=32B, sk=64B */
NEXTSSL_API int nextssl_root_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]);

/** Ed25519 sign: sig=64B */
NEXTSSL_API int nextssl_root_ed25519_sign(uint8_t sig[64],
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t sk[64]);

/** Ed25519 verify: returns 1 valid, 0 invalid */
NEXTSSL_API int nextssl_root_ed25519_verify(const uint8_t sig[64],
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t pk[32]);

/* ==========================================================================
 * Post-Quantum — KEM
 * ========================================================================== */

/** ML-KEM-768 keypair: pk=1184B, sk=2400B */
NEXTSSL_API int nextssl_root_mlkem768_keygen(uint8_t *pk, uint8_t *sk);

/** ML-KEM-768 encapsulate: ct=1088B, ss=32B */
NEXTSSL_API int nextssl_root_mlkem768_encaps(const uint8_t *pk,
                                             uint8_t *ct, uint8_t ss[32]);

/** ML-KEM-768 decapsulate: ct=1088B → ss=32B */
NEXTSSL_API int nextssl_root_mlkem768_decaps(const uint8_t *ct,
                                             const uint8_t *sk,
                                             uint8_t ss[32]);

/* ==========================================================================
 * Post-Quantum — Signatures
 * ========================================================================== */

/** ML-DSA-65 (Dilithium3) keypair: pk=1952B, sk=4032B */
NEXTSSL_API int nextssl_root_mldsa65_keygen(uint8_t *pk, uint8_t *sk);

/** ML-DSA-65 sign: sig up to 3309B, sets *sig_len */
NEXTSSL_API int nextssl_root_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t *sk);

/** ML-DSA-65 verify: returns 1 valid, 0 invalid */
NEXTSSL_API int nextssl_root_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t *pk);

/** ML-DSA-87 (Dilithium5) keypair: pk=2592B, sk=4896B */
NEXTSSL_API int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk);

/** ML-DSA-87 sign: sig up to 4627B, sets *sig_len */
NEXTSSL_API int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t *sk);

/** ML-DSA-87 verify: returns 1 valid, 0 invalid */
NEXTSSL_API int nextssl_root_mldsa87_verify(const uint8_t *sig, size_t sig_len,
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t *pk);

/* ==========================================================================
 * Password / KDF
 * ========================================================================== */

/**
 * Argon2id: explicit call with your own salt.
 * Use the profile-driven nextssl_password_hash() if you want auto-salt.
 */
NEXTSSL_API int nextssl_root_argon2id(const uint8_t *pw, size_t pw_len,
                                      const uint8_t *salt, size_t salt_len,
                                      uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_FULL_ROOT_H */
