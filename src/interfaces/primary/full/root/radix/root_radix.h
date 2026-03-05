/**
 * @file root/radix/root_radix.h
 * @brief NextSSL Root â€” Explicit radix encoding/decoding interface.
 *
 * Naming: nextssl_root_radix_<base>_{encode|decode}[_variant](...)
 *
 * All encode functions write a null-terminated string into output.
 * All decode functions write raw bytes and set *decoded_len.
 *
 * Return values (int):
 *   0          â€” success
 *   RADIX_ERROR_BUFFER_TOO_SMALL (-2) â€” output buffer too small
 *   RADIX_ERROR_INVALID_INPUT    (-1) â€” null pointer
 *   RADIX_ERROR_INVALID_ENCODING (-3) â€” bad characters in decode input
 *   RADIX_ERROR_INVALID_PADDING  (-4) â€” incorrect padding
 *   RADIX_ERROR_OVERFLOW         (-5) â€” arithmetic overflow (base58)
 *
 * Size helpers (from radix_common.h) let callers pre-compute buffer sizes:
 *   radix_base16_encoded_size(input_len)
 *   radix_base32_encoded_size(input_len)
 *   radix_base58_encoded_size(input_len)  â† conservative upper bound
 *   radix_base64_encoded_size(input_len)
 *   radix_base64url_encoded_size(input_len)
 */

#ifndef NEXTSSL_ROOT_RADIX_H
#define NEXTSSL_ROOT_RADIX_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"
#include "../../../../../utils/radix/radix_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * Base16 (hex)
 * ------------------------------------------------------------------ */

/** Encode to lowercase hex. output must be input_len*2+1 bytes. */
NEXTSSL_API int nextssl_root_radix_base16_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len);

/** Encode to uppercase hex. output must be input_len*2+1 bytes. */
NEXTSSL_API int nextssl_root_radix_base16_encode_upper(const uint8_t *input, size_t input_len,
                                                        char *output, size_t output_len);

/** Decode hex string (upper or lower). Sets *decoded_len on success. */
NEXTSSL_API int nextssl_root_radix_base16_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len);

/* ------------------------------------------------------------------
 * Base32 (RFC 4648)
 * ------------------------------------------------------------------ */

/** Encode to Base32. Padded with '='. */
NEXTSSL_API int nextssl_root_radix_base32_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len);

/** Decode Base32 string. */
NEXTSSL_API int nextssl_root_radix_base32_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len);

/* ------------------------------------------------------------------
 * Base58 (Bitcoin alphabet)
 * ------------------------------------------------------------------ */

/** Encode to Base58. Sets *encoded_len to actual output length. */
NEXTSSL_API int nextssl_root_radix_base58_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len,
                                                  size_t *encoded_len);

/** Decode Base58 string. */
NEXTSSL_API int nextssl_root_radix_base58_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len);

/* ------------------------------------------------------------------
 * Base64 (RFC 4648 standard alphabet, with padding)
 * ------------------------------------------------------------------ */

/** Encode to Base64. Padded with '='. */
NEXTSSL_API int nextssl_root_radix_base64_encode(const uint8_t *input, size_t input_len,
                                                  char *output, size_t output_len);

/** Decode Base64 string. */
NEXTSSL_API int nextssl_root_radix_base64_decode(const char *input, size_t input_len,
                                                  uint8_t *output, size_t output_len,
                                                  size_t *decoded_len);

/* ------------------------------------------------------------------
 * Base64url (RFC 4648 URL-safe alphabet â€” uses '-' and '_')
 * ------------------------------------------------------------------ */

/** Encode to Base64url with '=' padding. */
NEXTSSL_API int nextssl_root_radix_base64url_encode(const uint8_t *input, size_t input_len,
                                                     char *output, size_t output_len);

/** Encode to Base64url without padding (used in JWT, etc.). */
NEXTSSL_API int nextssl_root_radix_base64url_encode_nopad(const uint8_t *input, size_t input_len,
                                                           char *output, size_t output_len);

/** Decode Base64url string (accepts both padded and unpadded). */
NEXTSSL_API int nextssl_root_radix_base64url_decode(const char *input, size_t input_len,
                                                     uint8_t *output, size_t output_len,
                                                     size_t *decoded_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_RADIX_H */
