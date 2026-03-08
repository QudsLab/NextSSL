#ifndef RADIX_BASE16_H
#define RADIX_BASE16_H

#include "radix_common.h"

/**
 * Encode binary data to hexadecimal string (lowercase).
 * 
 * @param input     Input binary data
 * @param input_len Length of input in bytes
 * @param output    Output buffer (must be at least 2*input_len + 1 bytes)
 * @param output_len Size of output buffer
 * @return RADIX_SUCCESS or error code
 */
int radix_base16_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len);

/**
 * Encode binary data to hexadecimal string (uppercase).
 */
int radix_base16_encode_upper(const uint8_t *input, size_t input_len,
                               char *output, size_t output_len);

/**
 * Decode hexadecimal string to binary data.
 * Accepts both uppercase and lowercase hex digits.
 * 
 * @param input     Input hex string (NOT null-terminated required)
 * @param input_len Length of input string
 * @param output    Output buffer (must be at least input_len/2 bytes)
 * @param output_len Size of output buffer
 * @param decoded_len Pointer to store actual decoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base16_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len);

#endif // RADIX_BASE16_H
