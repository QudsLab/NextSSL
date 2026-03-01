#ifndef nextssl_UTILS_ENCODING_BASE64URL_H
#define nextssl_UTILS_ENCODING_BASE64URL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the required buffer size for a base64url string representation of binary data
 * of length bin_len. Includes space for the null terminator.
 * Base64URL does not use padding.
 */
size_t base64url_encoded_len(size_t bin_len);

/**
 * Returns the maximum required buffer size for binary data decoded from a base64url string
 * of length b64_len.
 */
size_t base64url_decoded_len(size_t b64_len);

/**
 * Encodes binary data to a null-terminated base64url string.
 * @param bin Pointer to binary data.
 * @param bin_len Length of binary data.
 * @param b64 Output buffer for base64url string.
 * @param b64_len Size of the output buffer.
 * @return 0 on success, -1 if buffer is too small.
 */
int base64url_encode(const uint8_t *bin, size_t bin_len, char *b64, size_t b64_len);

/**
 * Decodes a base64url string to binary data.
 * @param b64 Pointer to base64url string.
 * @param b64_len Length of base64url string.
 * @param bin Output buffer for binary data.
 * @param bin_len Size of the output buffer.
 * @return Number of bytes decoded on success, -1 on invalid character or buffer too small.
 */
int base64url_decode(const char *b64, size_t b64_len, uint8_t *bin, size_t bin_len);

#ifdef __cplusplus
}
#endif

#endif // nextssl_UTILS_ENCODING_BASE64URL_H
