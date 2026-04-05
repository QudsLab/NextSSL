/**
 * @file nextssl_errors.h
 * @brief NextSSL input sanitizer — error codes.
 *
 * These codes are returned only by the sanitizer layer (nss_sanitize and its
 * convenience wrappers).  Each algorithm subsystem defines its own error codes
 * in its own header.  Sanitizer errors never overlap with algorithm errors
 * because the sanitizer returns before any algorithm logic runs.
 *
 * LAYER      : 0 / common (no dependencies on other NextSSL headers)
 * VISIBILITY : internal
 * NAMESPACE  : NSS_ERR_*
 *
 * @version 1.0.0
 * @date 2026-03-13
 */

#ifndef NEXTSSL_COMMON_SANITIZER_ERRORS_H
#define NEXTSSL_COMMON_SANITIZER_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * SANITIZER ERROR CODES
 * ================================================================
 *
 * All codes are negative integers.  0 means success.
 *
 * NULL-input behaviour depends on the type tag:
 *
 *   Passthrough types (AUTO / BYTES / STRING / FILE):
 *     NULL input is ACCEPTED.  nss_sanitize sets out->data = NULL,
 *     out->length = 0.  The receiving algorithm decides whether an
 *     empty buffer is acceptable for its operation.
 *
 *   Decode types (HEX / BASE64):
 *     NULL input is REJECTED with NSS_ERR_NULL_INPUT because there
 *     is nothing to decode.  An empty string "" with HEX or BASE64
 *     is also rejected for the same reason.
 *
 * A length value of (size_t)-1 (i.e. SIZE_MAX via unsigned wrap) is
 * rejected with NSS_ERR_OVERFLOW regardless of type.
 */

/** NULL or empty input with a decode type (HEX / BASE64).
 *  Not returned for passthrough types — NULL is valid there. */
#define NSS_ERR_NULL_INPUT      (-1)

/** out == NULL.  The sanitizer has nowhere to write the result.
 *  This is the only hard NULL error that applies to ALL types. */
#define NSS_ERR_NULL_OUTPUT     (-2)

/** input_type is not one of the NSS_TYPE_* constants.
 *  Protects against callers accidentally passing an unrelated integer. */
#define NSS_ERR_UNKNOWN_TYPE    (-3)

/** Hex or base64 content is structurally invalid:
 *  - hex: odd digit count or character outside [0-9 a-f A-F]
 *  - base64: character outside alphabet, bad padding, or length not a
 *    multiple of 4 after padding normalisation */
#define NSS_ERR_BAD_ENCODING    (-4)

/** decode_buf is too small for the decoded output, or input_len is
 *  SIZE_MAX (impossible value indicating unsigned wrap / caller bug). */
#define NSS_ERR_OVERFLOW        (-5)

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_COMMON_SANITIZER_ERRORS_H */
