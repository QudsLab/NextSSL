/* base62.h — Base62 encoding
 *
 * Alphabet: 0-9 A-Z a-z  (62 characters, URL-safe, no padding)
 *
 * Encoding converts arbitrary binary to a big-endian base-62 number
 * string.  Leading zero bytes produce leading '0' characters.
 *
 * Maximum encoded size: ceil(input_len * log(256) / log(62)) + 1 (NUL)
 * A safe upper bound is BASE62_ENCODE_SIZE(n).
 */
#ifndef NEXTSSL_ENCODING_BASE62_H
#define NEXTSSL_ENCODING_BASE62_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Safe upper-bound for the output buffer of base62_encode().
 * Adds 1 for the NUL terminator. */
#define BASE62_ENCODE_SIZE(n) ((size_t)((n) * 14 / 10 + 4))

/**
 * Encode |srclen| bytes of |src| as a NUL-terminated Base62 string.
 *
 * @param src      Input bytes.
 * @param srclen   Number of input bytes.
 * @param dst      Output buffer.  Must hold at least BASE62_ENCODE_SIZE(srclen)
 *                 bytes (including the NUL terminator).
 * @param dstcap   Capacity of dst in bytes.
 * @param out_len  If non-NULL, receives the number of characters written
 *                 (not counting the NUL terminator).
 * @return 0 on success, -1 if dst is too small or input is NULL.
 */
int base62_encode(const uint8_t *src, size_t srclen,
                  char *dst, size_t dstcap,
                  size_t *out_len);

/**
 * Decode a NUL-terminated (or length-bounded) Base62 string.
 *
 * @param src      Input Base62 characters.
 * @param srclen   Number of input characters to read.
 * @param dst      Output buffer.
 * @param dstcap   Capacity of dst in bytes.
 * @param out_len  If non-NULL, receives the number of bytes written.
 * @return 0 on success, negative on error:
 *           -1  invalid input (NULL pointer or zero length)
 *           -2  output buffer too small
 *           -3  invalid character in input
 */
int base62_decode(const char *src, size_t srclen,
                  uint8_t *dst, size_t dstcap,
                  size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_BASE62_H */
