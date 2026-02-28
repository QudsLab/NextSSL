/**
 * @file sha256.h
 * @brief SHA-256 cryptographic hash function
 * 
 * Implementation of SHA-256 as specified in FIPS 180-4.
 * Provides 256-bit (32-byte) cryptographic hash output.
 * 
 * Standards Compliance:
 * - FIPS 180-4: Secure Hash Standard (SHS)
 * - NIST SP 800-107: Recommendation for Applications Using Approved Hash Algorithms
 * 
 * Security Properties:
 * - Collision resistance: ~2^256 operations
 * - Preimage resistance: ~2^256 operations
 * - Second preimage resistance: ~2^256 operations
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#ifndef NEXTSSL_SHA256_H
#define NEXTSSL_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 produces 32-byte (256-bit) output */
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

/**
 * @brief SHA-256 context structure
 * 
 * Internal state for incremental hashing.
 * Allows hashing of data in chunks.
 */
typedef struct {
    uint32_t state[8];      /* Current hash value (A-H) */
    uint64_t count;         /* Number of bytes processed */
    uint8_t  buffer[64];    /* Input buffer for partial blocks */
} sha256_ctx;

/**
 * @brief Initialize SHA-256 context
 * 
 * Sets initial hash values as specified in FIPS 180-4.
 * Must be called before first update.
 * 
 * @param ctx Context to initialize
 * 
 * @example
 *   sha256_ctx ctx;
 *   sha256_init(&ctx);
 *   sha256_update(&ctx, data, len);
 *   sha256_final(&ctx, hash);
 */
void sha256_init(sha256_ctx *ctx);

/**
 * @brief Process data through SHA-256
 * 
 * Can be called multiple times to hash data incrementally.
 * 
 * @param ctx Context to update
 * @param data Data to hash
 * @param len Length of data in bytes
 * 
 * @note data can be any length (including 0)
 * @note Can be called multiple times
 */
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize SHA-256 and produce digest
 * 
 * Applies padding and produces final 32-byte hash value.
 * After calling this, context must be re-initialized for reuse.
 * 
 * @param ctx Context to finalize
 * @param digest Output buffer (must be at least 32 bytes)
 * 
 * @note digest must have space for SHA256_DIGEST_SIZE bytes
 * @note Context is cleared after finalization
 */
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/**
 * @brief One-shot SHA-256 hashing
 * 
 * Convenience function to hash data in a single call.
 * Equivalent to init + update + final.
 * 
 * @param data Data to hash
 * @param len Length of data
 * @param digest Output buffer (32 bytes)
 * 
 * @example
 *   uint8_t hash[32];
 *   sha256(message, message_len, hash);
 */
void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_SHA256_H */
