/**
 * @file randomx.h
 * @brief RandomX proof-of-work algorithm interface
 * @layer partial
 * @category pow
 * @visibility hidden
 * 
 * RandomX - CPU-optimized PoW using random code execution.
 * Used in Monero. Designed to favor general-purpose CPUs over
 * specialized hardware (GPUs, ASICs, FPGAs).
 * 
 * @note Designed for cryptocurrency mining, not password hashing
 */

#ifndef NEXTSSL_PARTIAL_POW_RANDOMX_H
#define NEXTSSL_PARTIAL_POW_RANDOMX_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Initialize RandomX virtual machine
 * 
 * @param key Key blob (determines VM program)
 * @param key_len Length of key (typically 60 bytes)
 * @param flags Configuration flags (e.g., use hardware AES)
 * @param vm_handle Output handle for VM
 * @return 0 on success, negative on error
 * 
 * @note VM initialization is expensive. Reuse VM for multiple hashes.
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_randomx_init(
    const uint8_t *key, size_t key_len,
    uint32_t flags,
    void **vm_handle);

/**
 * Compute RandomX hash
 * 
 * @param vm_handle VM handle from init
 * @param input Input data to hash
 * @param input_len Length of input
 * @param hash Output buffer for 32-byte hash
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_randomx_hash(
    void *vm_handle,
    const uint8_t *input, size_t input_len,
    uint8_t hash[32]);

/**
 * Destroy RandomX virtual machine
 * 
 * @param vm_handle VM handle to destroy
 */
NEXTSSL_PARTIAL_API void nextssl_partial_pow_randomx_destroy(
    void *vm_handle);

/**
 * Self-test for RandomX implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pow_randomx_selftest(void);

#endif /* NEXTSSL_PARTIAL_POW_RANDOMX_H */
