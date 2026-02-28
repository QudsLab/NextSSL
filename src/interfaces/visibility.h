/**
 * @file visibility.h
 * @brief Symbol visibility control for NextSSL API layers
 * 
 * Defines visibility macros for 4-layer architecture:
 * - NEXTSSL_PARTIAL_API: Layer 1 (hidden from external users)
 * - NEXTSSL_BASE_API: Layer 2 (semi-public, library use)
 * - NEXTSSL_MAIN_API: Layer 3 (public high-level API)
 * - NEXTSSL_PRIMARY_API: Layer 4 (public unified API)
 * 
 * @platform Windows: __declspec(dllexport/dllimport)
 * @platform GCC/Clang: __attribute__((visibility("hidden/default")))
 */

#ifndef NEXTSSL_VISIBILITY_H
#define NEXTSSL_VISIBILITY_H

/* ========== Build Configuration Detection ========== */

/* Detect if building as shared library */
#if defined(_WIN32) || defined(__CYGWIN__)
    #define NEXTSSL_WINDOWS 1
    #ifdef NEXTSSL_BUILD_SHARED
        #define NEXTSSL_EXPORT __declspec(dllexport)
        #define NEXTSSL_IMPORT __declspec(dllimport)
    #else
        #define NEXTSSL_EXPORT
        #define NEXTSSL_IMPORT
    #endif
    #define NEXTSSL_HIDDEN
#else
    /* GCC/Clang on Unix-like systems */
    #if defined(__GNUC__) && __GNUC__ >= 4
        #define NEXTSSL_EXPORT __attribute__((visibility("default")))
        #define NEXTSSL_IMPORT __attribute__((visibility("default")))
        #define NEXTSSL_HIDDEN __attribute__((visibility("hidden")))
    #else
        #define NEXTSSL_EXPORT
        #define NEXTSSL_IMPORT
        #define NEXTSSL_HIDDEN
    #endif
#endif

/* Determine if we're building or using the library */
#ifdef NEXTSSL_BUILDING
    #define NEXTSSL_API NEXTSSL_EXPORT
#else
    #define NEXTSSL_API NEXTSSL_IMPORT
#endif

/* ========== Layer 1: Partial (Hidden) ========== */

/**
 * Layer 1 symbols - HIDDEN from external users
 * Only accessible within NextSSL library itself
 */
#define NEXTSSL_PARTIAL_API NEXTSSL_HIDDEN

/* ========== Layer 2: Base (Semi-Public) ========== */

/**
 * Layer 2 symbols - Semi-public
 * Available for library/framework integration but not recommended for end users
 */
#ifdef NEXTSSL_ENABLE_BASE_API
    #define NEXTSSL_BASE_API NEXTSSL_API
#else
    #define NEXTSSL_BASE_API NEXTSSL_HIDDEN
#endif

/* ========== Layer 3: Main (Public) ========== */

/**
 * Layer 3 symbols - Public high-level API
 * Recommended for most applications
 */
#define NEXTSSL_MAIN_API NEXTSSL_API

/* ========== Layer 4: Primary (Public Unified) ========== */

/**
 * Layer 4 symbols - Public unified API
 * Simplest interface for common use cases
 */
#define NEXTSSL_PRIMARY_API NEXTSSL_API

/* ========== Deprecation Warnings ========== */

#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_DEPRECATED __attribute__((deprecated))
    #define NEXTSSL_DEPRECATED_MSG(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
    #define NEXTSSL_DEPRECATED __declspec(deprecated)
    #define NEXTSSL_DEPRECATED_MSG(msg) __declspec(deprecated(msg))
#else
    #define NEXTSSL_DEPRECATED
    #define NEXTSSL_DEPRECATED_MSG(msg)
#endif

/* ========== Compiler Attributes ========== */

/* Mark function as not returning (for error handlers) */
#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
    #define NEXTSSL_NORETURN __declspec(noreturn)
#else
    #define NEXTSSL_NORETURN
#endif

/* Suggest compiler to inline function */
#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define NEXTSSL_INLINE __forceinline
#else
    #define NEXTSSL_INLINE inline
#endif

/* Mark function as pure (no side effects, return depends only on args) */
#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_PURE __attribute__((pure))
#else
    #define NEXTSSL_PURE
#endif

/* Mark function as const (no side effects, no memory access) */
#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_CONST __attribute__((const))
#else
    #define NEXTSSL_CONST
#endif

/* Warn if return value is ignored */
#if defined(__GNUC__) || defined(__clang__)
    #define NEXTSSL_MUST_CHECK __attribute__((warn_unused_result))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
    #define NEXTSSL_MUST_CHECK _Check_return_
#else
    #define NEXTSSL_MUST_CHECK
#endif

/* ========== Build Variant Detection ========== */

#ifdef NEXTSSL_BUILD_LITE
    #define NEXTSSL_VARIANT "lite"
    #define NEXTSSL_IS_LITE 1
    #define NEXTSSL_IS_FULL 0
#else
    #define NEXTSSL_VARIANT "full"
    #define NEXTSSL_IS_LITE 0
    #define NEXTSSL_IS_FULL 1
#endif

/* ========== Security Build Options ========== */

/* Enable if constant-time operations should be strictly enforced */
#ifdef NEXTSSL_STRICT_CONSTANT_TIME
    #define NEXTSSL_CONSTANT_TIME_REQUIRED 1
#else
    #define NEXTSSL_CONSTANT_TIME_REQUIRED 0
#endif

/* Enable memory sanitization checks (debug builds) */
#ifdef NEXTSSL_ENABLE_MEMORY_CHECKS
    #define NEXTSSL_MEMORY_CHECKS 1
#else
    #define NEXTSSL_MEMORY_CHECKS 0
#endif

/* ========== Platform-Specific Definitions ========== */

/* Detect endianness */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define NEXTSSL_BIG_ENDIAN 1
    #define NEXTSSL_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define NEXTSSL_BIG_ENDIAN 0
    #define NEXTSSL_LITTLE_ENDIAN 1
#elif defined(_WIN32) || defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
    /* Most common platforms are little-endian */
    #define NEXTSSL_BIG_ENDIAN 0
    #define NEXTSSL_LITTLE_ENDIAN 1
#else
    #define NEXTSSL_BIG_ENDIAN 0
    #define NEXTSSL_LITTLE_ENDIAN 0
    #define NEXTSSL_UNKNOWN_ENDIAN 1
#endif

/* Detect 64-bit platform */
#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(__ppc64__)
    #define NEXTSSL_64BIT 1
    #define NEXTSSL_32BIT 0
#else
    #define NEXTSSL_64BIT 0
    #define NEXTSSL_32BIT 1
#endif

/* Detect hardware AES support */
#if defined(__AES__) || (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86)))
    #define NEXTSSL_HAS_AES_NI 1
#else
    #define NEXTSSL_HAS_AES_NI 0
#endif

#endif /* NEXTSSL_VISIBILITY_H */
