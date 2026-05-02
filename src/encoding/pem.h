/* pem.h — PEM encode / decode (RFC 7468 / RFC 1421)
 *
 * PEM format:
 *   -----BEGIN <TYPE>-----\n
 *   <Base64, wrapped at 64 characters per line>\n
 *   -----END <TYPE>-----\n
 *
 * This implementation:
 *   - Encodes any DER/binary blob with a caller-supplied type label.
 *   - Decodes a single PEM block (first such block in the buffer).
 *   - Does not validate DER structure.
 *   - Line length fixed at 64 characters (RFC 7468 §2 recommendation).
 *   - Accepts base64 lines up to 80 characters on decode (lenient).
 *   - Type string may contain letters, digits, spaces, and hyphens.
 *
 * Size macro: PEM_ENCODE_SIZE(der_len, type_len) gives a safe upper bound
 * for the output buffer including the NUL terminator.
 */
#ifndef NEXTSSL_ENCODING_PEM_H
#define NEXTSSL_ENCODING_PEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEM_LINE_LEN     64u
#define PEM_MAX_TYPE_LEN 64u

/* Safe output buffer size for pem_encode():
 *   header + base64 content with newlines + footer + NUL
 *   Base64 content:  ceil(der_len / 3) * 4  characters + ceil(der_len / 48) '\n'
 *   Borders:  "-----BEGIN " + type + "-----\n" + "-----END " + type + "-----\n" */
#define PEM_ENCODE_SIZE(der_len, type_len) \
    (11u + (type_len) + 6u + 1u  \
   + (((der_len) + 2u) / 3u) * 4u + ((der_len) / 48u) + 2u \
   + 9u + (type_len) + 5u + 2u   \
   + 1u)

/* Error codes */
#define PEM_OK               0
#define PEM_ERR_INPUT       -1   /* NULL pointer */
#define PEM_ERR_BUFFER      -2   /* output buffer too small */
#define PEM_ERR_TYPE        -3   /* type string too long or contains invalid chars */
#define PEM_ERR_FORMAT      -4   /* no PEM block found or malformed header/footer */
#define PEM_ERR_BASE64      -5   /* base64 decode error */

/**
 * Encode |der_len| bytes of DER/binary data as a PEM block.
 *
 * @param type    NUL-terminated type label (e.g. "CERTIFICATE", "PRIVATE KEY").
 * @param der     Input bytes.
 * @param der_len Number of input bytes.
 * @param dst     Output buffer.  Must hold at least PEM_ENCODE_SIZE(der_len, strlen(type)).
 * @param dstcap  Capacity of dst.
 * @param out_len If non-NULL, receives bytes written (excluding NUL).
 * @return PEM_OK on success, negative on error.
 */
int pem_encode(const char *type,
               const uint8_t *der, size_t der_len,
               char *dst, size_t dstcap,
               size_t *out_len);

/**
 * Decode the first PEM block found in |pem|.
 *
 * @param pem        Input PEM text.
 * @param pem_len    Length of input (may contain multiple blocks; only first is decoded).
 * @param type_out   Output buffer for the type label (NUL-terminated).
 * @param type_cap   Capacity of type_out (at least PEM_MAX_TYPE_LEN+1).
 * @param der_out    Output buffer for the decoded bytes.
 * @param der_cap    Capacity of der_out.
 * @param der_len    Receives the number of bytes written.
 * @return PEM_OK on success, negative on error.
 */
int pem_decode(const char *pem, size_t pem_len,
               char *type_out, size_t type_cap,
               uint8_t *der_out, size_t der_cap, size_t *der_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_PEM_H */
