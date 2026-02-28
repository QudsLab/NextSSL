/**
 * @file radix.h
 * @brief Layer 2: Radix encoding/decoding aggregation
 * @layer base
 * @category radix
 * @visibility semi-public
 * 
 * Encoding and decoding functions for various radix representations.
 * 
 * **Formats supported:**
 * - Base64 (standard and URL-safe)
 * - Base32
 * - Hexadecimal
 * - Base58 (Bitcoin-style)
 * 
 * @security Constant-time implementations where applicable
 */

#ifndef NEXTSSL_BASE_RADIX_H
#define NEXTSSL_BASE_RADIX_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Base64 ========== */

/**
 * Encode to Base64 (standard alphabet, with padding)
 * 
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual encoded length
 * @return 0 on success, negative on error
 * 
 * @note Output size should be at least ((input_len + 2) / 3) * 4 + 1
 */
NEXTSSL_BASE_API int nextssl_base_radix_base64_encode(
    const uint8_t *input, size_t input_len,
    char *output, size_t output_size,
    size_t *output_len);

/**
 * Decode from Base64
 * 
 * @param input Input Base64 string
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual decoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_base64_decode(
    const char *input, size_t input_len,
    uint8_t *output, size_t output_size,
    size_t *output_len);

/**
 * Encode to Base64 URL-safe (RFC 4648)
 * 
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual encoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_base64url_encode(
    const uint8_t *input, size_t input_len,
    char *output, size_t output_size,
    size_t *output_len);

/**
 * Decode from Base64 URL-safe
 * 
 * @param input Input Base64 URL-safe string
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual decoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_base64url_decode(
    const char *input, size_t input_len,
    uint8_t *output, size_t output_size,
    size_t *output_len);

/* ========== Hexadecimal ========== */

/**
 * Encode to hexadecimal (lowercase)
 * 
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (at least input_len * 2 + 1 bytes)
 * @param output_size Size of output buffer
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_hex_encode(
    const uint8_t *input, size_t input_len,
    char *output, size_t output_size);

/**
 * Decode from hexadecimal
 * 
 * @param input Input hex string
 * @param input_len Length of input (must be even)
 * @param output Output buffer (at least input_len / 2 bytes)
 * @param output_size Size of output buffer
 * @param output_len Output for actual decoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_hex_decode(
    const char *input, size_t input_len,
    uint8_t *output, size_t output_size,
    size_t *output_len);

/* ========== Base58 (Bitcoin-style) ========== */

/**
 * Encode to Base58 (Bitcoin alphabet)
 * 
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual encoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_base58_encode(
    const uint8_t *input, size_t input_len,
    char *output, size_t output_size,
    size_t *output_len);

/**
 * Decode from Base58
 * 
 * @param input Input Base58 string
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @param output_len Output for actual decoded length
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_radix_base58_decode(
    const char *input, size_t input_len,
    uint8_t *output, size_t output_size,
    size_t *output_len);

/**
 * Self-test for radix operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_radix_selftest(void);

#endif /* NEXTSSL_BASE_RADIX_H */
