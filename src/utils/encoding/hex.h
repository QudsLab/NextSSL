#ifndef LEYLINE_UTILS_ENCODING_HEX_H
#define LEYLINE_UTILS_ENCODING_HEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the required buffer size for a hex string representation of binary data
 * of length bin_len. Includes space for the null terminator.
 */
size_t hex_encoded_len(size_t bin_len);

/**
 * Returns the maximum required buffer size for binary data decoded from a hex string
 * of length hex_len.
 */
size_t hex_decoded_len(size_t hex_len);

/**
 * Encodes binary data to a null-terminated hex string.
 * @param bin Pointer to binary data.
 * @param bin_len Length of binary data.
 * @param hex Output buffer for hex string.
 * @param hex_len Size of the output buffer (must be >= hex_encoded_len(bin_len)).
 * @return 0 on success, -1 if buffer is too small.
 */
int hex_encode(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_len);

/**
 * Decodes a hex string to binary data.
 * @param hex Pointer to hex string.
 * @param hex_len Length of hex string (excluding null terminator if present).
 * @param bin Output buffer for binary data.
 * @param bin_len Size of the output buffer (must be >= hex_decoded_len(hex_len)).
 * @return 0 on success, -1 on invalid character or buffer too small.
 */
int hex_decode(const char *hex, size_t hex_len, uint8_t *bin, size_t bin_len);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_UTILS_ENCODING_HEX_H
