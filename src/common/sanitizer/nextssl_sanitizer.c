/**
 * @file nextssl_sanitizer.c
 * @brief NextSSL input normalisation layer — implementation.
 *
 * See nextssl_sanitizer.h for full API documentation and design rationale.
 *
 * Dependencies (both live in src/common/encoding/):
 *   hex_decode()              from hex.h / hex.c
 *   radix_base64_decode()     from base64.h / base64.c (via radix_common.h)
 *
 * @version 1.0.0
 * @date 2026-03-13
 */

#include "nextssl_sanitizer.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/* Encoding helpers from src/common/encoding/ */
#include "../encoding/hex.h"
#include "../encoding/base64.h"

/* ================================================================
 * INTERNAL HELPERS
 * ================================================================ */

/** Write a zeroed NSS_Data to *out if out is not NULL. */
static void zero_out(NSS_Data *out)
{
    if (out) {
        out->data   = NULL;
        out->length = 0;
        out->type   = NSS_TYPE_AUTO;
    }
}

/* ================================================================
 * PRIMARY ENTRY POINT
 * ================================================================ */

int nss_sanitize(const void  *input,
                 size_t       input_len,
                 uint8_t      input_type,
                 uint8_t     *decode_buf,
                 size_t       decode_len,
                 NSS_Data    *out)
{
    /* Hard error: nowhere to write the result. */
    if (!out)
        return NSS_ERR_NULL_OUTPUT;

    zero_out(out);

    /* Reject impossible length (SIZE_MAX usually means unsigned wrap in caller). */
    if (input_len == (size_t)-1)
        return NSS_ERR_OVERFLOW;

    switch (input_type) {

    /* ---- Passthrough types ---- */
    case NSS_TYPE_AUTO:
    case NSS_TYPE_BYTES:
    case NSS_TYPE_STRING:
    case NSS_TYPE_FILE:
        /*
         * NULL input is valid for all passthrough types.
         * data=NULL + length=0 is a well-defined zero-length buffer.
         * The receiving algorithm decides whether that is acceptable.
         */
        out->data   = (const uint8_t *)input;
        out->length = input_len;
        out->type   = input_type;
        return 0;

    /* ---- Decode types ---- */
    case NSS_TYPE_HEX: {
        /*
         * NULL or empty hex string has nothing to decode — reject.
         * Odd digit count is structurally invalid hex — reject via
         * hex_decode() which will return -1 for bad input.
         */
        if (!input || input_len == 0)
            return NSS_ERR_NULL_INPUT;
        if (!decode_buf || decode_len < hex_decoded_len(input_len))
            return NSS_ERR_OVERFLOW;

        int rc = hex_decode((const char *)input, input_len,
                            decode_buf, decode_len);
        if (rc != 0)
            return NSS_ERR_BAD_ENCODING;

        out->data   = decode_buf;
        out->length = hex_decoded_len(input_len);
        out->type   = NSS_TYPE_HEX;
        return 0;
    }

    case NSS_TYPE_BASE64: {
        /*
         * NULL or empty base64 string has nothing to decode — reject.
         */
        if (!input || input_len == 0)
            return NSS_ERR_NULL_INPUT;

        size_t decoded_len = 0;
        /* radix_base64_decoded_size gives the worst-case upper bound. */
        size_t needed = radix_base64_decoded_size(input_len);
        if (!decode_buf || decode_len < needed)
            return NSS_ERR_OVERFLOW;

        int rc = radix_base64_decode((const char *)input, input_len,
                                     decode_buf, decode_len,
                                     &decoded_len);
        if (rc != RADIX_SUCCESS)
            return NSS_ERR_BAD_ENCODING;

        out->data   = decode_buf;
        out->length = decoded_len;
        out->type   = NSS_TYPE_BASE64;
        return 0;
    }

    default:
        return NSS_ERR_UNKNOWN_TYPE;
    }
}

/* ================================================================
 * CONVENIENCE WRAPPERS
 * ================================================================ */

int nss_sanitize_str(const char *str, NSS_Data *out)
{
    if (!out)
        return NSS_ERR_NULL_OUTPUT;

    /* strlen is safe: str==NULL is handled as zero-length. */
    size_t len = str ? strlen(str) : 0;
    return nss_sanitize(str, len, NSS_TYPE_STRING, NULL, 0, out);
}

int nss_sanitize_file(const uint8_t *buf, size_t len, NSS_Data *out)
{
    return nss_sanitize(buf, len, NSS_TYPE_FILE, NULL, 0, out);
}

int nss_sanitize_hex(const char *hex, size_t hex_len,
                     uint8_t *decode_buf, size_t decode_len,
                     NSS_Data *out)
{
    return nss_sanitize(hex, hex_len, NSS_TYPE_HEX,
                        decode_buf, decode_len, out);
}

int nss_sanitize_base64(const char *b64, size_t b64_len,
                        uint8_t *decode_buf, size_t decode_len,
                        NSS_Data *out)
{
    return nss_sanitize(b64, b64_len, NSS_TYPE_BASE64,
                        decode_buf, decode_len, out);
}
