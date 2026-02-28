/**
 * @file buffer.h
 * @brief Layer 1 (Partial) - Secure Buffer Management Interface
 * 
 * SECURITY CLASSIFICATION: HIDDEN (NEXTSSL_PARTIAL_API)
 * 
 * This interface provides secure memory operations including:
 * - Constant-time memory comparison
 * - Secure memory zeroing (compiler-barrier protected)
 * - Bounds-checked buffer operations
 * - Memory allocation with size limits
 * 
 * VISIBILITY: Hidden from external symbols
 * NAMESPACE: nextssl_partial_core_buffer_*
 * LAYER: 1 (Partial)
 * DEPENDENCIES: Layer 0 implementations only
 * 
 * THREAT MODEL:
 * - Prevents timing attacks via constant-time operations
 * - Prevents buffer overflows via bounds checking
 * - Prevents sensitive data leakage via secure zeroing
 * - Prevents compiler optimization of security-critical operations
 * 
 * @version 1.0.0
 * @date 2026-02-28
 */

#ifndef NEXTSSL_PARTIAL_CORE_BUFFER_H
#define NEXTSSL_PARTIAL_CORE_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplusplusplus
extern "C" {
#endif

/* ================================================================
 * VISIBILITY CONFIGURATION
 * ================================================================ */

#ifndef NEXTSSL_PARTIAL_API
    #if defined(_WIN32) || defined(__CYGWIN__)
        #define NEXTSSL_PARTIAL_API
    #elif defined(__GNUC__) && __GNUC__ >= 4
        #define NEXTSSL_PARTIAL_API __attribute__((visibility("hidden")))
    #else
        #define NEXTSSL_PARTIAL_API
    #endif
#endif

/* ================================================================
 * CONSTANTS
 * ================================================================ */

#define NEXTSSL_BUFFER_MAX_SIZE (SIZE_MAX / 2)  /* Prevent overflow */

/* ================================================================
 * SECURE MEMORY OPERATIONS
 * ================================================================ */

/**
 * @brief Secure memory zeroing (compiler-barrier protected)
 * 
 * SECURITY NOTES:
 * - Uses volatile pointer to prevent compiler optimization
 * - MUST NOT be optimized away by compiler
 * - Used for clearing sensitive data (keys, passwords, etc.)
 * - Constant-time operation
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length of memory region
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_buffer_secure_zero()
 */
NEXTSSL_PARTIAL_API void nextssl_partial_core_buffer_secure_zero(
    void *ptr,
    size_t len
);

/**
 * @brief Constant-time memory comparison
 * 
 * SECURITY NOTES:
 * - Timing-safe comparison (no early exit)
 * - MUST take same time regardless of where difference occurs
 * - Critical for cryptographic key/tag comparison
 * - Returns 0 if equal, non-zero if different
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, 1 if different
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Called by nextssl_base_buffer_constant_time_compare()
 */
NEXTSSL_PARTIAL_API int nextssl_partial_core_buffer_constant_time_compare(
    const void *a,
    const void *b,
    size_t len
);

/**
 * @brief Bounds-checked memory copy
 * 
 * SECURITY NOTES:
 * - Verifies dest_size >= src_len before copying
 * - Prevents buffer overflow
 * - Returns error if buffer too small
 * 
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source buffer
 * @param src_len Length of source data
 * @return 0 on success, -1 if buffer too small
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API int nextssl_partial_core_buffer_safe_copy(
    void *dest,
    size_t dest_size,
    const void *src,
    size_t src_len
);

/**
 * @brief Secure memory allocation with size limit
 * 
 * SECURITY NOTES:
 * - Enforces maximum allocation size
 * - Prevents integer overflow in size calculation
 * - Returns NULL if size exceeds limit
 * - Zeroes allocated memory
 * 
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @warning Caller MUST call nextssl_partial_core_buffer_secure_free()
 */
NEXTSSL_PARTIAL_API void* nextssl_partial_core_buffer_secure_alloc(
    size_t size
);

/**
 * @brief Secure memory free (zeroes before freeing)
 * 
 * SECURITY NOTES:
 * - Zeroes memory before deallocation
 * - Prevents sensitive data from remaining in freed memory
 * - Safe to call with NULL pointer
 * 
 * @param ptr Pointer to memory (can be NULL)
 * @param size Size of allocated memory (for zeroing)
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API void nextssl_partial_core_buffer_secure_free(
    void *ptr,
    size_t size
);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_BUFFER_H */

/**
 * SECURITY AUDIT NOTES:
 * 
 * 1. Constant-Time Requirements:
 *    - nextssl_partial_core_buffer_constant_time_compare() MUST be constant-time
 *    - No early exit based on data comparison
 *    - Verified by: tools/verify_constant_time.sh
 * 
 * 2. Compiler Barrier:
 *    - nextssl_partial_core_buffer_secure_zero() uses volatile
 *    - Prevents dead-store elimination
 *    - Verified manually in assembly output
 * 
 * 3. Bounds Checking:
 *    - All operations validate buffer sizes
 *    - Integer overflow prevention
 * 
 * 4. Memory Safety:
 *    - All sensitive data zeroed before free
 *    - Allocation size limits enforced
 * 
 * NEXT REVIEW: When Layer 2 (Base) implementation completed
 */
