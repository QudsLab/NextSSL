/**
 * @file secure_memory.h
 * @brief Secure memory operations for cryptographic code
 * 
 * Provides memory zeroing that won't be optimized away by compiler
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#ifndef NEXTSSL_SECURE_MEMORY_H
#define NEXTSSL_SECURE_MEMORY_H

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely zero memory (won't be optimized away)
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length of memory region
 */
static inline void nextssl_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    
    size_t original_len = len;  // Save original length
    
    // Use volatile to prevent compiler optimization
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
    
    // Additional barrier: force compiler to not optimize away the zeroing
    // Use original length, not decremented len
    __asm__ __volatile__("" ::: "memory");
    (void)original_len;  // Suppress unused warning
}

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_SECURE_MEMORY_H */
