#ifndef RADIX_BASE64URL_H
#define RADIX_BASE64URL_H

#include "radix_common.h"

/**
 * Encode binary data to base64url string (RFC 4648, URL-safe).
 * Alphabet: A-Z, a-z, 0-9, -, _
 * Uses '-' instead of '+', '_' instead of '/'.
 * Includes padding (=) to make length multiple of 4.
 * 
 * @param input     Input binary data
 * @param input_len Length of input in bytes
 * @param output    Output buffer (must be at least ((input_len+2)/3)*4 + 1 bytes)
 * @param output_len Size of output buffer
 * @return RADIX_SUCCESS or error code
 */
int radix_base64url_encode(const uint8_t *input, size_t input_len,
                           char *output, size_t output_len);

/**
 * Encode without padding (common in JWT and other URL contexts).
 */
int radix_base64url_encode_nopad(const uint8_t *input, size_t input_len,
                                 char *output, size_t output_len);

/**
 * Decode base64url string to binary data (RFC 4648, URL-safe).
 * Accepts both padded and unpadded input.
 * 
 * @param input     Input base64url string
 * @param input_len Length of input string
 * @param output    Output buffer
 * @param output_len Size of output buffer
 * @param decoded_len Pointer to store actual decoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base64url_decode(const char *input, size_t input_len,
                           uint8_t *output, size_t output_len,
                           size_t *decoded_len);

#endif // RADIX_BASE64URL_H
