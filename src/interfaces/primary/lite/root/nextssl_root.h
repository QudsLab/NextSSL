/**
 * @file root/nextssl_root.h
 * @brief NextSSL Lite — Explicit-Algorithm (Root) Interface
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
 * Lite variant limits: MD5, SHA-1, legacy AEAD are NOT available here.
 * Use the full variant's root/ for those.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_H
#define NEXTSSL_LITE_ROOT_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../config.h"  /* NEXTSSL_API, platform detection */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Hash — Explicit Algorithm
 * ========================================================================== */

/**
 * SHA-256: 32-byte output.
 * out must point to at least 32 bytes.
 */
NEXTSSL_API int nextssl_root_sha256(const uint8_t *data, size_t len,
                                    uint8_t out[32]);

/**
 * SHA-512: 64-byte output.
 * out must point to at least 64 bytes.
 */
NEXTSSL_API int nextssl_root_sha512(const uint8_t *data, size_t len,
                                    uint8_t out[64]);

/**
 * BLAKE3: variable output, defaults to 32 bytes (set out_len to desired size).
 * out must point to at least out_len bytes.
 */
NEXTSSL_API int nextssl_root_blake3(const uint8_t *data, size_t len,
                                    uint8_t *out, size_t out_len);

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

/** X25519 scalar × basepoint.  my_sk + their_pk → ss (32B). */
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
 * Post-Quantum
 * ========================================================================== */

/** ML-KEM-1024 keypair: pk=1568B, sk=3168B */
NEXTSSL_API int nextssl_root_mlkem1024_keygen(uint8_t *pk, uint8_t *sk);

/** ML-KEM-1024 encapsulate: writes ct=1568B and ss=32B */
NEXTSSL_API int nextssl_root_mlkem1024_encaps(const uint8_t *pk,
                                              uint8_t *ct, uint8_t ss[32]);

/** ML-KEM-1024 decapsulate: ct=1568B → ss=32B */
NEXTSSL_API int nextssl_root_mlkem1024_decaps(const uint8_t *ct,
                                              const uint8_t *sk,
                                              uint8_t ss[32]);

/** ML-DSA-87 keypair: pk=2592B, sk=4864B */
NEXTSSL_API int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk);

/** ML-DSA-87 sign: writes sig (max 4595B), sets *sig_len */
NEXTSSL_API int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t *sk);

/** ML-DSA-87 verify: returns 0 valid, non-zero invalid */
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

#endif /* NEXTSSL_LITE_ROOT_H */
