/**
 * @file timing.h
 * @brief Layer 1 (Partial) - Timing-Safe Operations Interface
 * 
 * SECURITY CLASSIFICATION: HIDDEN (NEXTSSL_PARTIAL_API)
 * 
 * This interface provides timing-safe operations to prevent timing attacks:
 * - Constant-time conditional selection
 * - Constant-time byte copying based on condition
 * - Constant-time equality testing
 * - Timing measurement utilities (for testing only)
 * 
 * VISIBILITY: Hidden from external symbols
 * NAMESPACE: nextssl_partial_core_timing_*
 * LAYER: 1 (Partial)
 * DEPENDENCIES: Layer 0 implementations only
 * 
 * THREAT MODEL:
 * - Prevents timing side-channels in cryptographic operations
 * - Ensures secret-dependent operations take constant time
 * - No early exit based on secret data
 * - No variable-time operations on secrets
 * 
 * @version 1.0.0
 * @date 2026-02-28
 */

#ifndef NEXTSSL_PARTIAL_CORE_TIMING_H
#define NEXTSSL_PARTIAL_CORE_TIMING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
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
 * CONSTANT-TIME SELECTION
 * ================================================================ */

/**
 * @brief Constant-time conditional selection (byte)
 * 
 * SECURITY NOTES:
 * - Returns 'a' if condition is true (non-zero), 'b' otherwise
 * - Takes constant time regardless of condition value
 * - No branching on secret data
 * - Used for implementing constant-time algorithms
 * 
 * @param condition Condition (non-zero = true, zero = false)
 * @param a Value to return if condition is true
 * @param b Value to return if condition is false
 * @return a if condition, else b
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Implementation: (((-condition) >> 7) & (a ^ b)) ^ b
 */
NEXTSSL_PARTIAL_API uint8_t nextssl_partial_core_timing_select_byte(
    uint8_t condition,
    uint8_t a,
    uint8_t b
);

/**
 * @brief Constant-time conditional selection (32-bit)
 * 
 * @param condition Condition (non-zero = true, zero = false)
 * @param a Value to return if condition is true
 * @param b Value to return if condition is false
 * @return a if condition, else b
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API uint32_t nextssl_partial_core_timing_select_u32(
    uint32_t condition,
    uint32_t a,
    uint32_t b
);

/**
 * @brief Constant-time conditional selection (64-bit)
 * 
 * @param condition Condition (non-zero = true, zero = false)
 * @param a Value to return if condition is true
 * @param b Value to return if condition is false
 * @return a if condition, else b
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API uint64_t nextssl_partial_core_timing_select_u64(
    uint64_t condition,
    uint64_t a,
    uint64_t b
);

/* ================================================================
 * CONSTANT-TIME EQUALITY TESTING
 * ================================================================ */

/**
 * @brief Constant-time equality test (byte)
 * 
 * SECURITY NOTES:
 * - Returns 1 if a == b, 0 otherwise
 * - Takes constant time regardless of values
 * - No early exit
 * 
 * @param a First value
 * @param b Second value
 * @return 1 if equal, 0 if different
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API uint8_t nextssl_partial_core_timing_equal_byte(
    uint8_t a,
    uint8_t b
);

/**
 * @brief Constant-time equality test (32-bit)
 * 
 * @param a First value
 * @param b Second value
 * @return 1 if equal, 0 if different
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API uint32_t nextssl_partial_core_timing_equal_u32(
    uint32_t a,
    uint32_t b
);

/* ================================================================
 * CONSTANT-TIME BUFFER OPERATIONS
 * ================================================================ */

/**
 * @brief Constant-time conditional copy
 * 
 * SECURITY NOTES:
 * - Copies src to dest if condition is true
 * - Always reads src, always writes dest (constant time)
 * - No branching on condition
 * 
 * @param dest Destination buffer
 * @param src Source buffer
 * @param len Length of buffers
 * @param condition Condition (non-zero = copy, zero = no-op)
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API void nextssl_partial_core_timing_conditional_copy(
    uint8_t *dest,
    const uint8_t *src,
    size_t len,
    uint8_t condition
);

/**
 * @brief Constant-time array lookup
 * 
 * SECURITY NOTES:
 * - Reads element at 'index' from 'array'
 * - Takes constant time regardless of index value
 * - Accesses all array elements (no early exit)
 * 
 * @param array Array of bytes
 * @param num_elements Number of elements in array
 * @param index Index to retrieve (must be < num_elements)
 * @return Value at array[index]
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @warning Caller MUST ensure index < num_elements
 */
NEXTSSL_PARTIAL_API uint8_t nextssl_partial_core_timing_array_lookup(
    const uint8_t *array,
    size_t num_elements,
    size_t index
);

/* ================================================================
 * TIMING MEASUREMENT (FOR TESTING ONLY)
 * ================================================================ */

/**
 * @brief Get high-resolution timestamp
 * 
 * SECURITY NOTES:
 * - FOR TESTING ONLY (constant-time verification)
 * - NOT for production cryptographic use
 * - Returns CPU cycle counter or high-resolution timer
 * 
 * @return Timestamp value (platform-specific)
 * 
 * @warning FOR TESTING ONLY. DO NOT USE IN PRODUCTION CODE.
 * @note Used by tools/verify_constant_time.sh
 */
NEXTSSL_PARTIAL_API uint64_t nextssl_partial_core_timing_get_timestamp(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_TIMING_H */

/**
 * SECURITY AUDIT NOTES:
 * 
 * 1. Constant-Time Verification:
 *    - All operations MUST be verified constant-time
 *    - Use dudect or ctgrind for verification
 *    - Verified by: tools/verify_constant_time.sh
 * 
 * 2. No Secret-Dependent Branching:
 *    - No if/else on secret data
 *    - No early returns based on secrets
 *    - All operations must touch same amount of data
 * 
 * 3. Implementation Requirements:
 *    - Use bitwise operations, not conditionals
 *    - Avoid compiler auto-vectorization unless verified
 *    - Check assembly output for branches
 * 
 * 4. Testing:
 *    - nextssl_partial_core_timing_get_timestamp() used for testing only
 *    - NOT exposed in upper layers
 * 
 * NEXT REVIEW: When Layer 2 (Base) implementation completed
 * CONSTANT-TIME VERIFICATION: REQUIRED before production use
 */
