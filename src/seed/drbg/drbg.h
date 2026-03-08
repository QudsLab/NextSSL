#ifndef NEXTSSL_COMMON_DRBG_H
#define NEXTSSL_COMMON_DRBG_H

#include <stddef.h>
#include <stdint.h>

/*
 * HMAC-DRBG using HMAC-SHA256 (NIST SP 800-90A)
 *
 * Unified DRBG for all NextSSL subsystems.  Previously split between
 * src/PQCrypto/common/drbg/ and src/utils/drbg/ — now a single canonical copy.
 *
 * Security properties:
 *   - Strictly fails when reseed_counter exceeds DRBG_RESEED_LIMIT.
 *   - drbg_wipe() zeroes the context on free.
 *   - Output is indistinguishable from random given a secret seed.
 */

#define DRBG_RESEED_LIMIT  (1u << 24)   /* Force reseed after 16M requests */

typedef struct {
    uint8_t  V[32];              /* 256-bit internal state vector              */
    uint8_t  Key[32];            /* 256-bit HMAC key                           */
    uint32_t reseed_counter;
} DRBG_CTX;

/*
 * drbg_init - Instantiate DRBG with seed material.
 * @ctx:      Caller-allocated context (need not be zeroed beforehand).
 * @seed:     Entropy + optional nonce, at least 32 bytes recommended.
 * @seed_len: Length of seed.
 */
void drbg_init(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len);

/*
 * drbg_reseed - Reseed an existing instantiation.
 * @ctx:      Existing DRBG context.
 * @seed:     Fresh entropy. Must be at least 32 bytes.
 * @seed_len: Length of seed.
 */
void drbg_reseed(DRBG_CTX *ctx, const uint8_t *seed, size_t seed_len);

/*
 * drbg_generate - Generate pseudo-random bytes.
 * @ctx:     Existing DRBG context.
 * @out:     Output buffer.
 * @out_len: Number of bytes to generate.
 * @return:  0 on success, -1 if reseed required (counter exceeded LIMIT).
 *
 * Caller must check return value for key-material generation.
 */
int drbg_generate(DRBG_CTX *ctx, uint8_t *out, size_t out_len);

/*
 * drbg_wipe - Securely zero and invalidate a context.
 */
void drbg_wipe(DRBG_CTX *ctx);

#endif /* NEXTSSL_COMMON_DRBG_H */
