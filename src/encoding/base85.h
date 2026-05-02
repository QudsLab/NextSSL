/* base85.h — Base85 encoding (RFC 1924 / Z85 compatible alphabet)
 *
 * Processes input in 4-byte groups → 5 ASCII characters.
 * Alphabet (85 chars, in value order):
 *   0-9  A-Z  a-z  ! # $ % & ( ) * + - ; < = > ? @ ^ _ ` { | } ~
 *
 * This is the "RFC 1924" alphabet (originally for IPv6 text compaction)
 * repurposed as a general binary encoding.  It has no grouping markers
 * (<~ ~> from Adobe Ascii85) and processes arbitrary-length input by
 * zero-padding the last incomplete 4-byte group.
 *
 * The padding length (0–3 bytes of zero added) is appended as the last
 * character: '~~' (no padding), '~0' (1 byte pad), '~1' (2), '~2' (3).
 * This is a minimal framing convention—interop with other Ascii85 libraries
 * requires the same convention or the caller must track the original length.
 *
 * Output size (encoded, including 2-byte length suffix, excluding NUL):
 *   BASE85_ENCODE_SIZE(n)
 */
#ifndef NEXTSSL_ENCODING_BASE85_H
#define NEXTSSL_ENCODING_BASE85_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Safe upper-bound for the base85_encode() output buffer (includes 2-byte
 * padding suffix and NUL terminator). */
#define BASE85_ENCODE_SIZE(n) (((size_t)(n) + 3) / 4 * 5 + 3)

/**
 * Encode |srclen| bytes into Base85.
 *
 * @param src     Input bytes.
 * @param srclen  Number of input bytes.
 * @param dst     Output buffer; must hold at least BASE85_ENCODE_SIZE(srclen).
 * @param dstcap  Capacity of dst.
 * @param out_len If non-NULL, receives the number of characters written
 *                (excluding the NUL terminator).
 * @return 0 on success, -1 on invalid args, -2 if dst is too small.
 */
int base85_encode(const uint8_t *src, size_t srclen,
                  char *dst, size_t dstcap,
                  size_t *out_len);

/**
 * Decode a Base85 string produced by base85_encode().
 *
 * @param src     Input Base85 characters (NUL-terminated or length-bounded).
 * @param srclen  Number of input characters.
 * @param dst     Output buffer.
 * @param dstcap  Capacity of dst.
 * @param out_len If non-NULL, receives the number of bytes written.
 * @return 0 on success, negative on error:
 *           -1  invalid input
 *           -2  output buffer too small
 *           -3  invalid character in input
 *           -4  malformed length suffix
 */
int base85_decode(const char *src, size_t srclen,
                  uint8_t *dst, size_t dstcap,
                  size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_BASE85_H */
