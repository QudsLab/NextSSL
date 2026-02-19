#ifndef RADIX_BASE32_H
#define RADIX_BASE32_H

#include "radix_common.h"

/**
 * Encode binary data to base32 string (RFC 4648).
 * Uses alphabet: A-Z, 2-7
 * Includes padding (=) to make length multiple of 8.
 * 
 * @param input     Input binary data
 * @param input_len Length of input in bytes
 * @param output    Output buffer (must be at least ((input_len+4)/5)*8 + 1 bytes)
 * @param output_len Size of output buffer
 * @return RADIX_SUCCESS or error code
 */
int radix_base32_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len);

/**
 * Decode base32 string to binary data (RFC 4648).
 * Accepts both uppercase and lowercase.
 * Padding (=) is required.
 * 
 * @param input     Input base32 string
 * @param input_len Length of input string
 * @param output    Output buffer
 * @param output_len Size of output buffer
 * @param decoded_len Pointer to store actual decoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base32_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len);

#endif // RADIX_BASE32_H
