/**
 * @file entropy.h
 * @brief Layer 1 (Partial) - Entropy Source Interface
 * 
 * @visibility HIDDEN (NEXTSSL_PARTIAL_API)
 * @layer 1
 * @category core
 * @subcategory entropy
 * 
 * This interface provides access to cryptographically secure entropy sources.
 * Supports multiple entropy sources: system (OS), hardware (CPU), and user-provided callbacks.
 * 
 * Security properties:
 * - High-quality entropy from OS-provided sources (BCryptGenRandom, getrandom, /dev/urandom)
 * - Hardware entropy from CPU instructions (RDRAND, RDSEED on x86, rndr/rndrrs on ARM)
 * - Entropy mixing/pooling for increased security
 * - Continuous health testing of entropy sources
 * 
 * @warning Always prefer system entropy sources over custom implementations
 * @warning Hardware entropy MUST be combined with system entropy (not used alone)
 * @warning Never use predictable sources (time, PIDs, etc.) as sole entropy
 * 
 * Entropy Source Priority:
 * 1. System entropy (BCryptGenRandom on Windows, getrandom() on Linux)
 * 2. Hardware entropy (RDRAND/RDSEED) - mixed with system entropy
 * 3. User-provided callbacks - use only when system sources unavailable
 * 
 * Thread safety: All functions are thread-safe (use internal locking).
 */

#ifndef NEXTSSL_PARTIAL_CORE_ENTROPY_H
#define NEXTSSL_PARTIAL_CORE_ENTROPY_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Entropy Source Types and Constants
 * ======================================================================== */

/**
 * @brief Opaque entropy context structure
 * 
 * Internal state:
 * - List of registered entropy sources
 * - Mixing pool for combining entropy from multiple sources
 * - Health test state (repetition count test, adaptive proportion test)
 * - Mutex for thread safety
 */
typedef struct nextssl_partial_core_entropy_ctx nextssl_partial_core_entropy_ctx_t;

/**
 * @brief Entropy source types
 */
typedef enum {
    NEXTSSL_ENTROPY_SOURCE_SYSTEM,       /**< OS-provided entropy (BCryptGenRandom, getrandom) */
    NEXTSSL_ENTROPY_SOURCE_HARDWARE,     /**< CPU hardware RNG (RDRAND, RDSEED) */
    NEXTSSL_ENTROPY_SOURCE_CUSTOM        /**< User-provided callback */
} nextssl_entropy_source_type_t;

/**
 * @brief Entropy source callback function
 * 
 * @param data User-provided context pointer
 * @param output Buffer to fill with entropy
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 * 
 * Requirements:
 * - MUST provide cryptographically secure random data
 * - MUST be non-blocking (or have very short timeout)
 * - SHOULD provide at least 128 bits of entropy per call
 */
typedef int (*nextssl_entropy_callback_t)(void *data, uint8_t *output, size_t len);

/* ========================================================================
 * Entropy Context Management
 * ======================================================================== */

/**
 * @brief Get required size for entropy context allocation
 * 
 * @return Size in bytes needed for context
 * 
 * @note Always call this before allocating context memory
 */
NEXTSSL_PARTIAL_API size_t
nextssl_partial_core_entropy_ctx_size(void);

/**
 * @brief Initialize entropy context
 * 
 * @param ctx Entropy context (must be pre-allocated)
 * @return 0 on success, negative error code on failure
 * 
 * Behavior:
 * - Automatically registers system entropy source (highest priority)
 * - Attempts to register hardware entropy source (if available)
 * - Initializes mixing pool
 * - Sets up health testing (NIST SP 800-90B)
 * 
 * @note This function is thread-safe and can be called from multiple threads
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_init(nextssl_partial_core_entropy_ctx_t *ctx);

/**
 * @brief Add custom entropy source to context
 * 
 * @param ctx Entropy context
 * @param callback User-provided entropy callback
 * @param user_data Context pointer passed to callback
 * @param threshold Minimum entropy bits per byte (0 = use default)
 * @return 0 on success, negative error code on failure
 * 
 * @warning Custom sources are LOWER priority than system/hardware sources
 * @warning threshold SHOULD be <= 8 bits per byte (typically 4-6 for most sources)
 * 
 * Use cases:
 * - Hardware security modules (HSMs)
 * - External entropy generators
 * - Additional mixing sources
 * 
 * @note Maximum 8 entropy sources can be registered
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_add_source(
    nextssl_partial_core_entropy_ctx_t *ctx,
    nextssl_entropy_callback_t callback,
    void *user_data,
    size_t threshold
);

/**
 * @brief Remove custom entropy source from context
 * 
 * @param ctx Entropy context
 * @param callback Callback to remove
 * @return 0 on success, negative error code if not found
 * 
 * @note Cannot remove built-in system/hardware sources
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_remove_source(
    nextssl_partial_core_entropy_ctx_t *ctx,
    nextssl_entropy_callback_t callback
);

/**
 * @brief Destroy entropy context and wipe state
 * 
 * @param ctx Entropy context to destroy
 * 
 * @note Performs secure memory wiping of mixing pool
 * @note Safe to call on already-destroyed or NULL contexts
 */
NEXTSSL_PARTIAL_API void
nextssl_partial_core_entropy_destroy(nextssl_partial_core_entropy_ctx_t *ctx);

/* ========================================================================
 * Entropy Generation Functions
 * ======================================================================== */

/**
 * @brief Generate cryptographically secure random bytes
 * 
 * @param ctx Entropy context (NULL = use default global context)
 * @param output Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 * 
 * Behavior:
 * - Collects entropy from all registered sources
 * - Mixes entropy in pool using SHA-512
 * - Performs health tests (repetition, proportion)
 * - Returns mixed entropy to caller
 * 
 * @warning If ctx is NULL, uses global context (initialized on first use)
 * @warning This function MAY block if entropy sources are exhausted (rare)
 * 
 * Error conditions:
 * - Returns error if health tests fail
 * - Returns error if all entropy sources fail
 * - Returns error if len is 0 or output is NULL
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_get(
    nextssl_partial_core_entropy_ctx_t *ctx,
    uint8_t *output,
    size_t len
);

/**
 * @brief Generate random bytes from specific source type
 * 
 * @param source_type Entropy source type to use
 * @param output Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 * 
 * @warning This bypasses mixing pool - use only for testing/diagnostics
 * @warning NEVER use hardware-only entropy in production (always mix with system)
 * 
 * Use cases:
 * - Testing entropy source quality
 * - Diagnostic tools
 * - Benchmarking
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_get_source(
    nextssl_entropy_source_type_t source_type,
    uint8_t *output,
    size_t len
);

/* ========================================================================
 * Entropy Source Information and Testing
 * ======================================================================== */

/**
 * @brief Check if specific entropy source is available
 * 
 * @param source_type Entropy source type to check
 * @return 1 if available, 0 if not available
 * 
 * Examples:
 * - On Windows: system=1, hardware=depends on CPU
 * - On Linux: system=1 (if kernel >= 3.17), hardware=depends on CPU
 * - On macOS: system=1, hardware=depends on CPU
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_source_available(nextssl_entropy_source_type_t source_type);

/**
 * @brief Get entropy quality estimate for source
 * 
 * @param source_type Entropy source type
 * @return Estimated entropy bits per byte (0.0 to 8.0), or -1.0 on error
 * 
 * Typical values:
 * - System entropy: 8.0 (full entropy)
 * - Hardware entropy: 6.0-8.0 (depends on CPU implementation)
 * - Custom sources: varies (set during add_source)
 * 
 * @note This is an ESTIMATE based on source type, not a measurement
 */
NEXTSSL_PARTIAL_API float
nextssl_partial_core_entropy_source_quality(nextssl_entropy_source_type_t source_type);

/**
 * @brief Perform health tests on entropy source
 * 
 * @param source_type Entropy source type to test
 * @param num_samples Number of test samples (min 1000, recommended 10000)
 * @return 0 if tests pass, negative error code if tests fail
 * 
 * Tests performed:
 * - Repetition Count Test (NIST SP 800-90B)
 * - Adaptive Proportion Test (NIST SP 800-90B)
 * - Chi-square test for uniformity
 * 
 * @warning This function is SLOW (generates num_samples bytes)
 * @warning Use only during startup or on-demand testing, not in hot path
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_health_test(
    nextssl_entropy_source_type_t source_type,
    size_t num_samples
);

/**
 * @brief Self-test entropy subsystem
 * 
 * @return 0 if all tests pass, negative error code on failure
 * 
 * Tests performed:
 * - Verify system entropy source is available
 * - Test entropy mixing function
 * - Run basic health tests on available sources
 * 
 * @note Should be run during library initialization
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_selftest(void);

/* ========================================================================
 * Platform-Specific Entropy Sources
 * ======================================================================== */

/**
 * @brief Get entropy from system source (direct access)
 * 
 * Platform implementations:
 * - Windows: BCryptGenRandom() with BCRYPT_USE_SYSTEM_PREFERRED_RNG
 * - Linux: getrandom() syscall (kernel >= 3.17) or /dev/urandom
 * - macOS: getentropy() or /dev/random
 * 
 * @param output Buffer to fill
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 * 
 * @note This is a low-level function - prefer nextssl_partial_core_entropy_get()
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_system(uint8_t *output, size_t len);

/**
 * @brief Get entropy from hardware source (direct access)
 * 
 * Platform implementations:
 * - x86/x64: RDRAND instruction (or RDSEED if available)
 * - ARM: rndr/rndrrs instructions (ARMv8.5+)
 * 
 * @param output Buffer to fill
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code if hardware RNG not available
 * 
 * @warning NEVER use this alone in production - always mix with system entropy
 * @note This is a low-level function - prefer nextssl_partial_core_entropy_get()
 */
NEXTSSL_PARTIAL_API int
nextssl_partial_core_entropy_hardware(uint8_t *output, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_ENTROPY_H */

/**
 * Implementation Notes:
 * 
 * 1. System Entropy Sources:
 *    Windows: BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG flag)
 *    Linux: getrandom() syscall (kernel 3.17+), fallback to /dev/urandom
 *    macOS: getentropy() (OSX 10.12+), fallback to /dev/random
 *    BSD: arc4random_buf() or /dev/urandom
 * 
 * 2. Hardware Entropy Sources:
 *    x86/x64: RDRAND (Intel IvyBridge+, AMD Ryzen+), RDSEED (newer CPUs)
 *    ARM: rndr/rndrrs instructions (ARMv8.5+)
 *    Detection: CPUID on x86, /proc/cpuinfo or getauxval on ARM
 * 
 * 3. Entropy Mixing:
 *    - Uses SHA-512 to mix entropy from multiple sources
 *    - Pool size: 512 bytes (4096 bits)
 *    - Collection: 256 bytes from each source -> mix -> extract
 *    - Forward secrecy: pool state updated after each extraction
 * 
 * 4. Health Testing (NIST SP 800-90B):
 *    - Repetition Count Test: detects stuck-at faults
 *    - Adaptive Proportion Test: detects bias in output
 *    - Cutoff values based on expected entropy per sample
 *    - Continuous testing during operation (startup and runtime)
 * 
 * 5. Thread Safety:
 *    - Global context protected by mutex
 *    - Per-context operations use context-specific locks
 *    - Lock-free fast path for system entropy (when no mixing required)
 * 
 * 6. Error Handling:
 *    - System source failures are CRITICAL (abort or panic)
 *    - Hardware source failures degrade gracefully (use system only)
 *    - Custom source failures logged but don't abort (other sources used)
 * 
 * SECURITY AUDIT NOTES:
 * - [ ] Verify system entropy source is always available
 * - [ ] Check hardware entropy detection and fallback logic
 * - [ ] Review mixing function (SHA-512 based)
 * - [ ] Validate health test implementation (NIST SP 800-90B compliance)
 * - [ ] Test thread safety under concurrent load
 * - [ ] Verify secure memory wiping in destroy()
 * - [ ] Check that hardware entropy is NEVER used alone
 */
