/**
 * @file error.h
 * @brief Layer 1 (Partial) - Error Handling Interface
 * 
 * SECURITY CLASSIFICATION: HIDDEN (NEXTSSL_PARTIAL_API)
 * 
 * This interface provides error handling mechanisms:
 * - Error code definitions
 * - Error string conversion
 * - Error logging with security context
 * - Stack trace capture (debug builds only)
 * 
 * VISIBILITY: Hidden from external symbols
 * NAMESPACE: nextssl_partial_core_error_*
 * LAYER: 1 (Partial)
 * DEPENDENCIES: Layer 0 implementations only
 * 
 * THREAT MODEL:
 * - Prevents information leakage via error messages
 * - No sensitive data in error strings
 * - Controlled error propagation (no silent failures)
 * - Audit trail for security-relevant errors
 * 
 * @version 1.0.0
 * @date 2026-02-28
 */

#ifndef NEXTSSL_PARTIAL_CORE_ERROR_H
#define NEXTSSL_PARTIAL_CORE_ERROR_H

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
 * ERROR CODE CATEGORIES
 * ================================================================ */

/* Success */
#define NEXTSSL_SUCCESS                     0

/* General errors (1-99) */
#define NEXTSSL_ERROR_UNKNOWN              -1
#define NEXTSSL_ERROR_NULL_POINTER         -2
#define NEXTSSL_ERROR_INVALID_ARGUMENT     -3
#define NEXTSSL_ERROR_OUT_OF_MEMORY        -4
#define NEXTSSL_ERROR_BUFFER_TOO_SMALL     -5
#define NEXTSSL_ERROR_NOT_IMPLEMENTED      -6

/* Input validation errors (100-199) */
#define NEXTSSL_ERROR_INVALID_LENGTH       -100
#define NEXTSSL_ERROR_LENGTH_TOO_LARGE     -101
#define NEXTSSL_ERROR_INVALID_FORMAT       -102
#define NEXTSSL_ERROR_INVALID_ENCODING     -103

/* Cryptographic errors (200-299) */
#define NEXTSSL_ERROR_CRYPTO_FAILED        -200
#define NEXTSSL_ERROR_AUTH_FAILED          -201
#define NEXTSSL_ERROR_VERIFICATION_FAILED  -202
#define NEXTSSL_ERROR_INVALID_KEY          -203
#define NEXTSSL_ERROR_INVALID_NONCE        -204
#define NEXTSSL_ERROR_INVALID_SIGNATURE    -205

/* System errors (300-399) */
#define NEXTSSL_ERROR_IO_FAILED            -300
#define NEXTSSL_ERROR_ENTROPY_FAILED       -301
#define NEXTSSL_ERROR_PLATFORM_UNSUPPORTED -302

/* Layer violation errors (400-499) - should never occur in production */
#define NEXTSSL_ERROR_LAYER_VIOLATION      -400
#define NEXTSSL_ERROR_DEPENDENCY_MISSING   -401
#define NEXTSSL_ERROR_SYMBOL_NOT_FOUND     -402

/* ================================================================
 * ERROR SEVERITY LEVELS
 * ================================================================ */

typedef enum {
    NEXTSSL_SEVERITY_INFO    = 0,  /* Informational */
    NEXTSSL_SEVERITY_WARNING = 1,  /* Warning (operation continues) */
    NEXTSSL_SEVERITY_ERROR   = 2,  /* Error (operation fails) */
    NEXTSSL_SEVERITY_FATAL   = 3   /* Fatal (cannot continue) */
} nextssl_severity_t;

/* ================================================================
 * ERROR CONTEXT
 * ================================================================ */

/**
 * @brief Error context structure
 * 
 * SECURITY NOTES:
 * - Does NOT contain sensitive data
 * - Safe to log and display to user
 * - Contains only non-sensitive diagnostic information
 */
typedef struct {
    int code;                        /* Error code (see above) */
    nextssl_severity_t severity;     /* Severity level */
    const char *function;            /* Function name where error occurred */
    const char *file;                /* Source file (can be NULL in release) */
    int line;                        /* Source line (0 in release) */
    const char *message;             /* Human-readable message */
} nextssl_error_context_t;

/* ================================================================
 * ERROR OPERATIONS
 * ================================================================ */

/**
 * @brief Get error string for error code
 * 
 * SECURITY NOTES:
 * - Returns non-sensitive error description
 * - Safe to display to users
 * - No internal implementation details leaked
 * 
 * @param code Error code
 * @return Human-readable error string (never NULL)
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API const char* nextssl_partial_core_error_string(int code);

/**
 * @brief Create error context
 * 
 * @param code Error code
 * @param severity Severity level
 * @param function Function name (use __func__)
 * @param file Source file (use __FILE__ or NULL)
 * @param line Source line (use __LINE__ or 0)
 * @param message Additional message (can be NULL)
 * @return Error context structure
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
NEXTSSL_PARTIAL_API nextssl_error_context_t nextssl_partial_core_error_create(
    int code,
    nextssl_severity_t severity,
    const char *function,
    const char *file,
    int line,
    const char *message
);

/**
 * @brief Log error context
 * 
 * SECURITY NOTES:
 * - Logs to configured error handler
 * - NEVER logs sensitive data (keys, plaintext, etc.)
 * - Safe for production use
 * - Can be disabled via build flags
 * 
 * @param ctx Error context to log
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 * @note Logging disabled if NEXTSSL_DISABLE_ERROR_LOGGING defined
 */
NEXTSSL_PARTIAL_API void nextssl_partial_core_error_log(
    const nextssl_error_context_t *ctx
);

/**
 * @brief Set custom error handler
 * 
 * @param handler Custom error handler function (NULL to use default)
 * 
 * @warning This is a PARTIAL interface. Use Layer 2+ for production.
 */
typedef void (*nextssl_error_handler_fn)(const nextssl_error_context_t *ctx);

NEXTSSL_PARTIAL_API void nextssl_partial_core_error_set_handler(
    nextssl_error_handler_fn handler
);

/* ================================================================
 * HELPER MACROS (INTERNAL USE ONLY)
 * ================================================================ */

#ifdef NEXTSSL_DEBUG
    #define NEXTSSL_ERROR_CREATE(code, severity, msg) \
        nextssl_partial_core_error_create(code, severity, __func__, __FILE__, __LINE__, msg)
#else
    #define NEXTSSL_ERROR_CREATE(code, severity, msg) \
        nextssl_partial_core_error_create(code, severity, __func__, NULL, 0, msg)
#endif

#define NEXTSSL_ERROR_LOG(code, severity, msg) \
    do { \
        nextssl_error_context_t _err = NEXTSSL_ERROR_CREATE(code, severity, msg); \
        nextssl_partial_core_error_log(&_err); \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PARTIAL_CORE_ERROR_H */

/**
 * SECURITY AUDIT NOTES:
 * 
 * 1. Information Leakage Prevention:
 *    - Error messages contain NO sensitive data
 *    - No keys, plaintext, internal state in errors
 *    - Safe to log and display
 * 
 * 2. Error Propagation:
 *    - All errors MUST be logged or returned
 *    - No silent failures allowed
 *    - Critical errors trigger abort() in debug builds
 * 
 * 3. Debug vs Release:
 *    - Debug: Includes file/line information
 *    - Release: No file/line (reduces binary size, prevents info leak)
 * 
 * 4. Custom Error Handlers:
 *    - Users can set custom handler via Layer 2+
 *    - Default handler logs to stderr
 *    - Production: Should log to secure audit trail
 * 
 * 5. Error Code Ranges:
 *    - Organized by category for easy identification
 *    - Negative values (standard convention)
 *    - Zero = success only
 * 
 * NEXT REVIEW: When Layer 2 (Base) implementation completed
 */
