/**
 * @file nextssl_sanitizer.h
 * @brief NextSSL input normalisation layer.
 *
 * The sanitizer converts any caller-supplied data into a single internal
 * byte representation (NSS_Data) before it reaches an algorithm.  It is
 * a *normaliser*, not a gatekeeper:
 *
 *   - It never decides whether the data is acceptable for an algorithm.
 *   - It never imposes length constraints.
 *   - It only rejects input that it structurally *cannot convert* (unknown
 *     type tag, malformed hex/base64, NULL with a decode type, SIZE_MAX
 *     length indicating an unsigned overflow in the caller).
 *
 * NULL-input rules:
 *   Passthrough types (AUTO / BYTES / STRING / FILE) — NULL accepted.
 *     Produces NSS_Data{data=NULL, length=0}.  Algorithm decides.
 *   Decode types (HEX / BASE64) — NULL or empty-string rejected with
 *     NSS_ERR_NULL_INPUT; there is nothing to decode.
 *
 * Integration:
 *   Every public-facing function that accepts external caller data must
 *   call nss_sanitize() once at entry.  After that, the NSS_Data* is
 *   forwarded to internal functions directly — no repeated conversion.
 *   Algorithm-to-algorithm calls that already hold an NSS_Data must NOT
 *   call nss_sanitize() again.
 *
 * LAYER      : 0 / common
 * VISIBILITY : internal
 * NAMESPACE  : nss_sanitize*
 * DEPENDENCIES: nextssl_data.h, nextssl_errors.h
 *
 * @version 1.0.0
 * @date 2026-03-13
 */

#ifndef NEXTSSL_COMMON_SANITIZER_H
#define NEXTSSL_COMMON_SANITIZER_H

#include <stddef.h>
#include <stdint.h>
#include "nextssl_data.h"
#include "nextssl_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * PRIMARY ENTRY POINT
 * ================================================================ */

/**
 * nss_sanitize — convert caller input to NSS_Data.
 *
 * @param input       Pointer to caller data.  May be NULL for passthrough
 *                    types (AUTO/BYTES/STRING/FILE); must be non-NULL and
 *                    non-empty for decode types (HEX/BASE64).
 * @param input_len   Byte count of input.  Pass 0 for passthrough types if
 *                    the buffer is empty.  May not be SIZE_MAX.
 * @param input_type  One of the NSS_TYPE_* constants.  Pass NSS_TYPE_AUTO
 *                    (0) for raw binary — this is the correct default for
 *                    all uint8_t* / binary data and requires no change from
 *                    existing callers.
 * @param decode_buf  Caller-supplied buffer for decoded output.  Required
 *                    for NSS_TYPE_HEX and NSS_TYPE_BASE64; pass NULL for
 *                    passthrough types (it is ignored).
 * @param decode_len  Byte capacity of decode_buf.  Must be large enough to
 *                    hold the decoded result; use hex_decoded_len() or
 *                    radix_base64_decoded_size() to compute the size.
 * @param out         Must not be NULL.  Receives the normalised NSS_Data on
 *                    success; zeroed on failure.
 *
 * @return 0 on success.
 * @return NSS_ERR_NULL_INPUT   if input is NULL/empty with HEX or BASE64.
 * @return NSS_ERR_NULL_OUTPUT  if out is NULL.
 * @return NSS_ERR_UNKNOWN_TYPE if input_type is not a valid NSS_TYPE_*.
 * @return NSS_ERR_BAD_ENCODING if hex/base64 content is structurally invalid.
 * @return NSS_ERR_OVERFLOW     if decode_buf is too small or input_len==SIZE_MAX.
 *
 * Consistency guarantee:
 *   Identical (input, input_len, input_type) produces byte-identical NSS_Data
 *   every call.  This is what makes hash(msg) == hashVerify(msg, hash(msg))
 *   work reliably: both sides normalise msg the same way.
 *
 * Subsystem integration table (algorithm-owned constraints listed separately):
 *
 *   Hash (all 40 algos)       — message: any length accepted by algorithm
 *   PoW (Argon2/scrypt/...)   — password: >=1 byte (algorithm constraint)
 *   PoW compute (randomx...)  — context data: non-empty (algorithm constraint)
 *   AEAD encrypt/decrypt      — plaintext/AAD: key must be exact size (algo)
 *   MAC (HMAC/CMAC/Poly1305)  — message + key: key exact size (algo)
 *   KDF (HKDF/PBKDF2/...)     — IKM/salt/info: IKM>=1 byte (algo)
 *   Keygen — password path    — password: >=1 byte (algo)
 *   Keygen — hash path        — seed: algo-defined minimum (algo)
 *   Keygen — kdf path         — IKM/salt/info: IKM>=1 byte (algo)
 *   Keygen — hd path          — master+path: master>=seed size (algo)
 *   UDBF                      — entropy feed: >=MIN_FEED_LEN=32B (algo)
 *   Signature sign/verify     — message: any length (algo)
 *   Encoding                  — raw bytes or encoded string (algo validates)
 *   Password hash verify      — password: >=1 byte; <=algo max (algo)
 *   DHCM / ECDH / ML-KEM      — public key / shared secret (algo validates)
 *   ECC primitives            — point / scalar (algo validates)
 *   DRBG seed                 — entropy: algo-defined minimum (algo)
 */
int nss_sanitize(const void  *input,
                 size_t       input_len,
                 uint8_t      input_type,
                 uint8_t     *decode_buf,
                 size_t       decode_len,
                 NSS_Data    *out);

/* ================================================================
 * CONVENIENCE WRAPPERS
 * ================================================================ */

/**
 * nss_sanitize_str — null-terminated C string → NSS_TYPE_STRING NSS_Data.
 *
 * Zero-copy passthrough.  str may be an empty string "" (length == 0).
 * str == NULL is accepted and produces NSS_Data{data=NULL, length=0}.
 *
 * @param str  Null-terminated UTF-8 / ASCII string.  May be NULL.
 * @param out  Must not be NULL.
 * @return 0 on success, NSS_ERR_NULL_OUTPUT if out is NULL.
 */
int nss_sanitize_str(const char *str, NSS_Data *out);

/**
 * nss_sanitize_file — pre-read file buffer → NSS_TYPE_FILE NSS_Data.
 *
 * Zero-copy passthrough.  The caller is responsible for reading the file;
 * no FILE* or path string ever enters the library.  buf==NULL or len==0
 * is accepted; algorithm decides if an empty file buffer is acceptable.
 *
 * @param buf  Pre-read file bytes.  May be NULL.
 * @param len  Byte count of buf.
 * @param out  Must not be NULL.
 * @return 0 on success, NSS_ERR_NULL_OUTPUT if out is NULL.
 */
int nss_sanitize_file(const uint8_t *buf, size_t len, NSS_Data *out);

/**
 * nss_sanitize_hex — hex string → decoded bytes → NSS_TYPE_HEX NSS_Data.
 *
 * Thin wrapper around nss_sanitize with NSS_TYPE_HEX.
 * hex must be non-NULL and non-empty.  decode_buf must be at least
 * hex_decoded_len(hex_len) bytes.
 *
 * @param hex         Hex-encoded string (case-insensitive, no "0x" prefix).
 * @param hex_len     Length of hex in bytes (not including null terminator).
 * @param decode_buf  Caller-supplied output buffer for decoded bytes.
 * @param decode_len  Capacity of decode_buf.
 * @param out         Must not be NULL.
 * @return 0 on success, NSS_ERR_* on failure.
 */
int nss_sanitize_hex(const char *hex, size_t hex_len,
                     uint8_t *decode_buf, size_t decode_len,
                     NSS_Data *out);

/**
 * nss_sanitize_base64 — base64 string → decoded bytes → NSS_TYPE_BASE64 NSS_Data.
 *
 * Thin wrapper around nss_sanitize with NSS_TYPE_BASE64.
 * b64 must be non-NULL and non-empty.  decode_buf must be at least
 * radix_base64_decoded_size(b64_len) bytes.
 *
 * @param b64         Standard base64 string (RFC 4648, padding required).
 * @param b64_len     Length of b64 in bytes (not including null terminator).
 * @param decode_buf  Caller-supplied output buffer for decoded bytes.
 * @param decode_len  Capacity of decode_buf.
 * @param out         Must not be NULL.
 * @return 0 on success, NSS_ERR_* on failure.
 */
int nss_sanitize_base64(const char *b64, size_t b64_len,
                        uint8_t *decode_buf, size_t decode_len,
                        NSS_Data *out);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_COMMON_SANITIZER_H */
