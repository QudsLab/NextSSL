/**
 * @file utils.h
 * @brief Layer 2: Utility functions aggregation
 * @layer base
 * @category utils
 * @visibility semi-public
 * 
 * Utility functions for cryptographic operations.
 * 
 * **Functions provided:**
 * - Secure memory operations
 * - Constant-time comparisons
 * - Random number generation
 * - Timing-safe selection
 * 
 * @security All functions designed to resist timing attacks where applicable
 */

#ifndef NEXTSSL_BASE_UTILS_H
#define NEXTSSL_BASE_UTILS_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Secure Memory Operations ========== */

/**
 * Securely zero memory (cannot be optimized away by compiler)
 * 
 * @param buf Buffer to zero
 * @param len Length of buffer
 * 
 * @security Use after handling sensitive data
 */
NEXTSSL_BASE_API void nextssl_base_utils_secure_zero(
    void *buf,
    size_t len);

/**
 * Secure memory copy with bounds checking
 * 
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source buffer
 * @param src_len Length to copy
 * @return 0 on success, negative on error
 * 
 * @security Prevents buffer overflows
 */
NEXTSSL_BASE_API int nextssl_base_utils_secure_copy(
    void *dest, size_t dest_size,
    const void *src, size_t src_len);

/* ========== Constant-Time Operations ========== */

/**
 * Constant-time memory comparison
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 1 if equal, 0 if not equal
 * 
 * @security Timing does not leak position of differences
 */
NEXTSSL_BASE_API int nextssl_base_utils_constant_time_compare(
    const void *a,
    const void *b,
    size_t len);

/**
 * Constant-time byte equality test
 * 
 * @param a First byte
 * @param b Second byte
 * @return 0xFF if equal, 0x00 if not equal
 */
NEXTSSL_BASE_API uint8_t nextssl_base_utils_constant_time_eq_byte(
    uint8_t a,
    uint8_t b);

/**
 * Constant-time conditional select
 * 
 * @param condition Select condition (0 or 1)
 * @param true_val Value if condition is 1
 * @param false_val Value if condition is 0
 * @return Selected value
 * 
 * @security Execution time independent of condition
 */
NEXTSSL_BASE_API uint32_t nextssl_base_utils_constant_time_select(
    uint32_t condition,
    uint32_t true_val,
    uint32_t false_val);

/* ========== Random Number Generation ========== */

/**
 * Generate cryptographically secure random bytes
 * 
 * @param out Output buffer
 * @param len Number of bytes (max 1MB)
 * @return 0 on success, negative on error
 * 
 * @security Uses DRBG reseeded from system entropy
 */
NEXTSSL_BASE_API int nextssl_base_utils_random_bytes(
    uint8_t *out,
    size_t len);

/**
 * Generate random uint32_t
 * 
 * @param out Pointer to output
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_utils_random_uint32(
    uint32_t *out);

/**
 * Generate random uint64_t
 * 
 * @param out Pointer to output
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_utils_random_uint64(
    uint64_t *out);

/* ========== Self-test ========== */

/**
 * Self-test for utility operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_utils_selftest(void);

#endif /* NEXTSSL_BASE_UTILS_H */
