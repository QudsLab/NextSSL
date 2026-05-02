/* base58check.h — Base58Check encoding (Bitcoin / IPFS address format)
 *
 * Base58Check = Base58 + 4-byte checksum (first 4 bytes of SHA-256(SHA-256(data)))
 *
 * Wire format:  base58( version_byte || payload || checksum[0..3] )
 *
 * This module wraps the common/encoding/base58 implementation for the
 * encoding step and calls SHA-256 directly from src/hash/fast/sha256.h
 * for the checksum computation.  It does NOT depend on the hash registry.
 */
#ifndef NEXTSSL_ENCODING_BASE58CHECK_H
#define NEXTSSL_ENCODING_BASE58CHECK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define BASE58CHECK_OK              0
#define BASE58CHECK_ERR_INPUT      -1   /* NULL pointer or zero-length payload */
#define BASE58CHECK_ERR_BUFFER     -2   /* output buffer too small */
#define BASE58CHECK_ERR_ENCODE     -3   /* base58 encode failure */
#define BASE58CHECK_ERR_DECODE     -4   /* base58 decode failure */
#define BASE58CHECK_ERR_CHECKSUM   -5   /* checksum mismatch on decode */
#define BASE58CHECK_ERR_TRUNCATED  -6   /* decoded bytes too short to hold checksum */

/* Maximum payload length supported.  Larger inputs hit the allocator-free
 * stack buffer inside base58check_encode. */
#define BASE58CHECK_MAX_PAYLOAD    512u

/* Conservative upper bound on encoded character count (excl NUL) */
#define BASE58CHECK_ENCODE_SIZE(payload_len) \
    ((size_t)((1u + (payload_len) + 4u) * 138u / 100u + 4u))

/**
 * Encode:  version || payload  →  Base58Check NUL-terminated string.
 *
 * @param version     1-byte version prefix (e.g. 0x00 for mainnet P2PKH).
 * @param payload     The payload bytes to encode.
 * @param payload_len Number of payload bytes.
 * @param dst         Output buffer.  Size must be >= BASE58CHECK_ENCODE_SIZE(payload_len).
 * @param dstcap      Capacity of dst.
 * @param out_len     If non-NULL, receives the number of characters written
 *                    (not counting NUL).
 * @return BASE58CHECK_OK on success, negative on error.
 */
int base58check_encode(uint8_t version,
                       const uint8_t *payload, size_t payload_len,
                       char *dst, size_t dstcap,
                       size_t *out_len);

/**
 * Decode:  Base58Check string  →  version + payload (checksum verified).
 *
 * @param src         Input Base58Check string.
 * @param srclen      Length of input string (not counting any NUL).
 * @param version_out Receives the decoded version byte.
 * @param payload_out Output buffer for the payload bytes.
 * @param payload_cap Capacity of payload_out.
 * @param payload_len Receives the number of payload bytes written.
 * @return BASE58CHECK_OK on success; BASE58CHECK_ERR_CHECKSUM if the
 *         checksum bytes do not match; other negative on other errors.
 */
int base58check_decode(const char *src, size_t srclen,
                       uint8_t *version_out,
                       uint8_t *payload_out, size_t payload_cap,
                       size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_BASE58CHECK_H */
