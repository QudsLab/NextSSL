/**
 * @file root/radix/root_radix.c
 * @brief NextSSL Root — Radix encoding/decoding implementation.
 *
 * Thin wrappers over the flat radix utilities in src/utils/radix/.
 */

#include "root_radix.h"
#include "../root_internal.h"

#include "../../../../../utils/radix/base16.h"
#include "../../../../../utils/radix/base32.h"
#include "../../../../../utils/radix/base58.h"
#include "../../../../../utils/radix/base64.h"
#include "../../../../../utils/radix/base64url.h"

/* =========================================================================
 * Base16
 * ====================================================================== */

NEXTSSL_API int nextssl_root_radix_base16_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base16_encode(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base16_encode_upper(const uint8_t *input, size_t input_len,
                                                        char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base16_encode_upper(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base16_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len) {
    if (!input || !output || !decoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base16_decode(input, input_len, output, output_len, decoded_len);
}

/* =========================================================================
 * Base32
 * ====================================================================== */

NEXTSSL_API int nextssl_root_radix_base32_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base32_encode(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base32_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len) {
    if (!input || !output || !decoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base32_decode(input, input_len, output, output_len, decoded_len);
}

/* =========================================================================
 * Base58
 * ====================================================================== */

NEXTSSL_API int nextssl_root_radix_base58_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len,
                                                  size_t *encoded_len) {
    if (!input || !output || !encoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base58_encode(input, input_len, output, output_len, encoded_len);
}

NEXTSSL_API int nextssl_root_radix_base58_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len) {
    if (!input || !output || !decoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base58_decode(input, input_len, output, output_len, decoded_len);
}

/* =========================================================================
 * Base64
 * ====================================================================== */

NEXTSSL_API int nextssl_root_radix_base64_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base64_encode(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base64_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len) {
    if (!input || !output || !decoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base64_decode(input, input_len, output, output_len, decoded_len);
}

/* =========================================================================
 * Base64url
 * ====================================================================== */

NEXTSSL_API int nextssl_root_radix_base64url_encode(const uint8_t *input, size_t input_len,
                                                     char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base64url_encode(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base64url_encode_nopad(const uint8_t *input, size_t input_len,
                                                           char *output, size_t output_len) {
    if (!input || !output) return RADIX_ERROR_INVALID_INPUT;
    return radix_base64url_encode_nopad(input, input_len, output, output_len);
}

NEXTSSL_API int nextssl_root_radix_base64url_decode(const char *input, size_t input_len,
                                                     uint8_t *output, size_t output_len,
                                                     size_t *decoded_len) {
    if (!input || !output || !decoded_len) return RADIX_ERROR_INVALID_INPUT;
    return radix_base64url_decode(input, input_len, output, output_len, decoded_len);
}
