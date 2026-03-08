#ifndef RADIX_BASE58_H
#define RADIX_BASE58_H

#include "radix_common.h"

/**
 * Encode binary data to base58 string (Bitcoin alphabet).
 * Alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
 * (Excludes: 0, O, I, l to avoid confusion)
 * NO PADDING.
 * 
 * @param input     Input binary data
 * @param input_len Length of input in bytes
 * @param output    Output buffer (must be at least input_len*2 + 1 bytes)
 * @param output_len Size of output buffer
 * @param encoded_len Pointer to store actual encoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base58_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len,
                        size_t *encoded_len);

/**
 * Decode base58 string to binary data (Bitcoin alphabet).
 * 
 * @param input     Input base58 string
 * @param input_len Length of input string
 * @param output    Output buffer (must be at least input_len bytes)
 * @param output_len Size of output buffer
 * @param decoded_len Pointer to store actual decoded length (can be NULL)
 * @return RADIX_SUCCESS or error code
 */
int radix_base58_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len);

#endif // RADIX_BASE58_H
