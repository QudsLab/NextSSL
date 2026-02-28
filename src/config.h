/**
 * @file config.h
 * @brief NextSSL Build Configuration
 * 
 * This file provides platform detection, compiler attributes, and
 * visibility control for the NextSSL library.
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#ifndef NEXTSSL_CONFIG_H
#define NEXTSSL_CONFIG_H

/* ========================================================================
 * Version Information
 * ======================================================================== */

#define NEXTSSL_VERSION_MAJOR 0
#define NEXTSSL_VERSION_MINOR 0
#define NEXTSSL_VERSION_PATCH 1
#define NEXTSSL_VERSION_STRING "0.0.1-beta"

/* ========================================================================
 * Platform Detection
 * ======================================================================== */

#if defined(_WIN32) || defined(_WIN64)
    #define NEXTSSL_PLATFORM_WINDOWS 1
    #define NEXTSSL_PLATFORM_UNIX 0
#elif defined(__unix__) || defined(__unix) || defined(__linux__) || \
      defined(__APPLE__) || defined(__MACH__)
    #define NEXTSSL_PLATFORM_WINDOWS 0
    #define NEXTSSL_PLATFORM_UNIX 1
#else
    #define NEXTSSL_PLATFORM_WINDOWS 0
    #define NEXTSSL_PLATFORM_UNIX 0
#endif

/* ========================================================================
 * Compiler Detection
 * ======================================================================== */

#if defined(_MSC_VER)
    #define NEXTSSL_COMPILER_MSVC 1
    #define NEXTSSL_COMPILER_GCC 0
    #define NEXTSSL_COMPILER_CLANG 0
#elif defined(__clang__)
    #define NEXTSSL_COMPILER_MSVC 0
    #define NEXTSSL_COMPILER_GCC 0
    #define NEXTSSL_COMPILER_CLANG 1
#elif defined(__GNUC__)
    #define NEXTSSL_COMPILER_MSVC 0
    #define NEXTSSL_COMPILER_GCC 1
    #define NEXTSSL_COMPILER_CLANG 0
#else
    #define NEXTSSL_COMPILER_MSVC 0
    #define NEXTSSL_COMPILER_GCC 0
    #define NEXTSSL_COMPILER_CLANG 0
#endif

/* ========================================================================
 * Symbol Visibility Control
 * ======================================================================== */

/**
 * @brief Public API - Exported symbols (Layer 4: Primary API)
 * 
 * These symbols are always visible to library users.
 */
#if NEXTSSL_PLATFORM_WINDOWS
    /* On Windows (MSVC or MinGW/GCC), dllexport/dllimport is required */
    #ifdef NEXTSSL_BUILDING_DLL
        #define NEXTSSL_API __declspec(dllexport)
    #else
        #define NEXTSSL_API __declspec(dllimport)
    #endif
#elif NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_API __attribute__((visibility("default")))
#else
    #define NEXTSSL_API
#endif

/**
 * @brief Main API - Conditionally exported (Layer 3: Main API)
 * 
 * Exposed only if NEXTSSL_EXPOSE_MAIN_API is defined.
 * Default: hidden (use Primary API instead)
 */
#ifdef NEXTSSL_EXPOSE_MAIN_API
    #define NEXTSSL_MAIN_API NEXTSSL_API
#else
    #if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
        #define NEXTSSL_MAIN_API __attribute__((visibility("hidden")))
    #else
        #define NEXTSSL_MAIN_API
    #endif
#endif

/**
 * @brief Base API - Conditionally exported (Layer 2: Base API)
 * 
 * Exposed only if NEXTSSL_EXPOSE_BASE_API is defined.
 * Default: hidden (use Primary or Main API instead)
 */
#ifdef NEXTSSL_EXPOSE_BASE_API
    #define NEXTSSL_BASE_API NEXTSSL_API
#else
    #if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
        #define NEXTSSL_BASE_API __attribute__((visibility("hidden")))
    #else
        #define NEXTSSL_BASE_API
    #endif
#endif

/**
 * @brief Partial API - Always hidden (Layer 1: Partial/Internal API)
 * 
 * These symbols are NEVER exported, even in debug builds.
 * Only for internal use within the library.
 */
#if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_PARTIAL_API __attribute__((visibility("hidden")))
#else
    #define NEXTSSL_PARTIAL_API
#endif

/**
 * @brief Internal symbols - Always hidden
 * 
 * Layer 0 primitives and utility functions.
 */
#if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_INTERNAL __attribute__((visibility("hidden")))
#else
    #define NEXTSSL_INTERNAL
#endif

/* ========================================================================
 * Compiler Attributes
 * ======================================================================== */

/**
 * @brief Mark function as deprecated
 */
#if NEXTSSL_COMPILER_MSVC
    #define NEXTSSL_DEPRECATED __declspec(deprecated)
#elif NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_DEPRECATED __attribute__((deprecated))
#else
    #define NEXTSSL_DEPRECATED
#endif

/**
 * @brief Suggest function result should not be ignored
 */
#if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_MUST_USE __attribute__((warn_unused_result))
#else
    #define NEXTSSL_MUST_USE
#endif

/**
 * @brief Mark function as no-return (terminates process)
 */
#if NEXTSSL_COMPILER_MSVC
    #define NEXTSSL_NORETURN __declspec(noreturn)
#elif NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_NORETURN __attribute__((noreturn))
#else
    #define NEXTSSL_NORETURN
#endif

/**
 * @brief Suggest function is unlikely to be called (branch prediction)
 */
#if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_UNLIKELY __attribute__((cold))
#else
    #define NEXTSSL_UNLIKELY
#endif

/**
 * @brief Request function inlining
 */
#if NEXTSSL_COMPILER_MSVC
    #define NEXTSSL_INLINE __forceinline
#elif NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
    #define NEXTSSL_INLINE __attribute__((always_inline)) inline
#else
    #define NEXTSSL_INLINE inline
#endif

/* ========================================================================
 * Security Features
 * ======================================================================== */

/**
 * @brief Enable constant-time operations (default: ON)
 * 
 * When enabled, timing-sensitive operations use constant-time algorithms
 * to prevent timing side-channel attacks.
 */
#ifndef NEXTSSL_CONSTANT_TIME
    #define NEXTSSL_CONSTANT_TIME 1
#endif

/**
 * @brief Enable memory locking (default: ON on Unix, conditional on Windows)
 * 
 * When enabled, sensitive memory pages are locked to prevent swapping.
 */
#ifndef NEXTSSL_ENABLE_MLOCK
    #if NEXTSSL_PLATFORM_UNIX
        #define NEXTSSL_ENABLE_MLOCK 1
    #else
        #define NEXTSSL_ENABLE_MLOCK 0
    #endif
#endif

/**
 * @brief Enable stack protection (default: ON in debug)
 * 
 * Adds canaries to detect buffer overflows.
 */
#ifndef NEXTSSL_STACK_PROTECTION
    #ifdef NDEBUG
        #define NEXTSSL_STACK_PROTECTION 0
    #else
        #define NEXTSSL_STACK_PROTECTION 1
    #endif
#endif

/* ========================================================================
 * Build Variant
 * ======================================================================== */

/**
 * @brief Lite variant (9 algorithms, ~300KB binary)
 * 
 * Includes:
 * - Hash: SHA-256, SHA-512, BLAKE3
 * - AEAD: AES-256-GCM, ChaCha20-Poly1305
 * - KDF: HKDF, Argon2id
 * - KEM: Kyber1024 (post-quantum)
 * - Sign: Dilithium5 (post-quantum)
 */
#ifndef NEXTSSL_BUILD_LITE
    #define NEXTSSL_BUILD_LITE 0
#endif

/**
 * @brief Full variant (134 algorithms, ~2.5MB binary)
 * 
 * Includes everything in Lite plus legacy/specialized algorithms.
 */
#ifndef NEXTSSL_BUILD_FULL
    #define NEXTSSL_BUILD_FULL 0
#endif

/* Validate build variant */
#if NEXTSSL_BUILD_LITE && NEXTSSL_BUILD_FULL
    #error "Cannot define both NEXTSSL_BUILD_LITE and NEXTSSL_BUILD_FULL"
#endif

/* Default to Lite if nothing specified */
#if !NEXTSSL_BUILD_LITE && !NEXTSSL_BUILD_FULL
    #define NEXTSSL_BUILD_LITE 1
#endif

/* ========================================================================
 * Feature Flags
 * ======================================================================== */

/**
 * @brief Enable threading support (default: ON)
 */
#ifndef NEXTSSL_ENABLE_THREADS
    #define NEXTSSL_ENABLE_THREADS 1
#endif

/**
 * @brief Enable hardware acceleration (default: ON)
 * 
 * Uses CPU-specific instructions (AES-NI, AVX2, NEON, etc.) when available.
 */
#ifndef NEXTSSL_ENABLE_HARDWARE_ACCEL
    #define NEXTSSL_ENABLE_HARDWARE_ACCEL 1
#endif

/**
 * @brief Enable assembly optimizations (default: ON for GCC/Clang)
 */
#ifndef NEXTSSL_ENABLE_ASM
    #if NEXTSSL_COMPILER_GCC || NEXTSSL_COMPILER_CLANG
        #define NEXTSSL_ENABLE_ASM 1
    #else
        #define NEXTSSL_ENABLE_ASM 0
    #endif
#endif

/* ========================================================================
 * Debug and Testing
 * ======================================================================== */

/**
 * @brief Enable assertions (default: ON in debug)
 */
#ifndef NEXTSSL_ENABLE_ASSERT
    #ifdef NDEBUG
        #define NEXTSSL_ENABLE_ASSERT 0
    #else
        #define NEXTSSL_ENABLE_ASSERT 1
    #endif
#endif

/**
 * @brief Enable self-tests (default: ON in debug)
 * 
 * Runs built-in test vectors at library initialization.
 */
#ifndef NEXTSSL_ENABLE_SELFTEST
    #ifdef NDEBUG
        #define NEXTSSL_ENABLE_SELFTEST 0
    #else
        #define NEXTSSL_ENABLE_SELFTEST 1
    #endif
#endif

/**
 * @brief Enable fuzzing instrumentation (default: OFF)
 */
#ifndef NEXTSSL_ENABLE_FUZZING
    #define NEXTSSL_ENABLE_FUZZING 0
#endif

/* ========================================================================
 * Limits and Constants
 * ======================================================================== */

/**
 * @brief Maximum input size for hashing (1GB)
 * 
 * Prevents DoS attacks from extremely large inputs.
 */
#define NEXTSSL_MAX_HASH_INPUT_SIZE (1024ULL * 1024 * 1024)

/**
 * @brief Maximum password length for Argon2 (128 bytes)
 */
#define NEXTSSL_MAX_PASSWORD_LENGTH 128

/**
 * @brief Argon2 memory cost (128 MB)
 */
#define NEXTSSL_ARGON2_MEMORY_COST (128 * 1024)

/**
 * @brief Argon2 time cost (4 iterations)
 */
#define NEXTSSL_ARGON2_TIME_COST 4

/* ========================================================================
 * Error Codes (Centralized)
 * ======================================================================== */

#define NEXTSSL_SUCCESS                  0
#define NEXTSSL_ERROR_NULL_POINTER      -1
#define NEXTSSL_ERROR_INVALID_ALGORITHM -2
#define NEXTSSL_ERROR_INVALID_PARAMETER -3
#define NEXTSSL_ERROR_BUFFER_TOO_SMALL  -4
#define NEXTSSL_ERROR_NOT_IMPLEMENTED   -5
#define NEXTSSL_ERROR_OUT_OF_MEMORY     -6
#define NEXTSSL_ERROR_INTERNAL          -7
#define NEXTSSL_ERROR_VERIFICATION      -8
#define NEXTSSL_ERROR_INPUT_TOO_LARGE   -9

#endif /* NEXTSSL_CONFIG_H */
