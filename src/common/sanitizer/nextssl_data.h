/**
 * @file nextssl_data.h
 * @brief NextSSL unified input data representation.
 *
 * Defines NSS_Data — the single internal byte buffer type passed through
 * every algorithm entry point after the sanitizer normalises caller input.
 *
 * LAYER      : 0 / common (no dependencies on other NextSSL headers)
 * VISIBILITY : internal — never exported in the public API
 * NAMESPACE  : NSS_*
 *
 * @version 1.0.0
 * @date 2026-03-13
 */

#ifndef NEXTSSL_COMMON_SANITIZER_DATA_H
#define NEXTSSL_COMMON_SANITIZER_DATA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * TYPE TAGS
 * ================================================================
 *
 * Passed by the caller as a hint to nss_sanitize().  After the call
 * the tag is stored in NSS_Data.type for informational use only —
 * algorithms must not branch on it.
 *
 * Zero-copy (passthrough) types:  AUTO, BYTES, STRING, FILE
 * Decode types:                   HEX, BASE64
 */

/** Default: raw binary passthrough.  No conversion performed.  Existing
 *  callers that hand a uint8_t* + size_t need no changes — they can omit
 *  the type argument entirely and pass 0 / NSS_TYPE_AUTO. */
#define NSS_TYPE_AUTO    0x00

/** Explicit raw byte buffer.  Semantically identical to AUTO; use when
 *  the call site benefits from a self-documenting annotation. */
#define NSS_TYPE_BYTES   0x01

/** UTF-8 / ASCII text.  Passed through as-is (no charset conversion). */
#define NSS_TYPE_STRING  0x02

/** Pre-read file buffer.  The caller reads the file; this is zero-copy. */
#define NSS_TYPE_FILE    0x03

/** Hex-encoded text (case-insensitive, no prefix).  Decoded to raw bytes
 *  into caller-supplied decode_buf.  Requires even number of hex digits. */
#define NSS_TYPE_HEX     0x04

/** Standard base64 (RFC 4648 §4, padding required).  Decoded to raw bytes
 *  into caller-supplied decode_buf. */
#define NSS_TYPE_BASE64  0x05

/* ================================================================
 * INTERNAL DATA STRUCTURE
 * ================================================================ */

/**
 * NSS_Data — immutable normalised byte buffer.
 *
 * Fields must NEVER be modified after nss_sanitize() writes them.
 * Internal functions that need a sub-slice create a new NSS_Data
 * pointing into the same buffer with adjusted offset/length; the
 * original is left intact.
 *
 * Invariants:
 *   - length == 0  is valid.  data may be NULL when length == 0.
 *   - data != NULL when length > 0.
 *   - type holds the NSS_TYPE_* tag used during sanitisation.
 */
typedef struct {
    const uint8_t *data;   /**< Pointer to normalised bytes (never modified). */
    size_t         length; /**< Byte count. 0 is valid; algorithm decides.    */
    uint8_t        type;   /**< NSS_TYPE_* tag (informational after init).    */
} NSS_Data;

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_COMMON_SANITIZER_DATA_H */
