#ifndef RADIX_BASE64_H
#define RADIX_BASE64_H

#include "radix_common.h"

/**
 * Encode binary data to base64 string (RFC 4648).
 * Alphabet: A-Z, a-z, 0-9, +, /
 * Includes padding (=) to make length multiple of 4.
 * 
 * @param input     Input binary data
 * @param input_len Length of input in bytes
 * @param output    Output buffer (must be at least ((input_len+2)/3)*4 + 1 bytes)
 * @param output_len Size of output buffer
 * @return RADIX_SUCCESS or error code
 */
int radix_base64_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len);

/**
 * Decode base64 string to binary data (RFC 4648).
 * Padding (=) is required.
 * 
 * @param input     Input base64 string
 * @param input_len Length of input string
 * @param output    Output buffer
 * @param output_len Size of output buffer
 * @param decoded_len Pointer to store actual decoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base64_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len);

#endif // RADIX_BASE64_H
