/* bech32.h — Bech32 and Bech32m encoding (BIP 0173 / BIP 0350)
 *
 * Bech32:  BIP 0173 — used for SegWit v0 witness programs (P2WPKH, P2WSH).
 *          Checksum constant M = 1.
 * Bech32m: BIP 0350 — used for SegWit v1+ (Taproot, P2TR) and future versions.
 *          Checksum constant M = 0x2BC830A3.
 *
 * Encoding:  lowercase HRP + "1" separator + data (5-bit groups) + 6-char checksum.
 * HRP:       1–83 ASCII characters, all lowercase.
 * Data:      arbitrary 5-bit-per-symbol array (NOT raw bytes; caller must
 *            convert via bech32_convert_bits() first).
 *
 * Maximum total encoded length: 90 characters (BIP 0173 §3).
 * This implementation enforces an 83-byte HRP limit and 64 data-5bit symbols
 * limit per that spec's constraints.
 */
#ifndef NEXTSSL_ENCODING_BECH32_H
#define NEXTSSL_ENCODING_BECH32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum total Bech32 string length (BIP 0173) */
#define BECH32_MAX_TOTAL_LEN   90u
/* Maximum HRP length */
#define BECH32_MAX_HRP_LEN     83u

/* Error codes */
#define BECH32_OK               0
#define BECH32_ERR_INPUT       -1   /* NULL pointer or bad length */
#define BECH32_ERR_BUFFER      -2   /* output buffer too small */
#define BECH32_ERR_HRP         -3   /* HRP contains invalid characters */
#define BECH32_ERR_CHECKSUM    -4   /* checksum verification failed */
#define BECH32_ERR_LENGTH      -5   /* encoded string exceeds 90 chars */
#define BECH32_ERR_SEPARATOR   -6   /* '1' separator not found */
#define BECH32_ERR_CHAR        -7   /* invalid character in data part */

/**
 * Encode a Bech32 or Bech32m string.
 *
 * @param hrp       Human-readable part (lowercase ASCII, NUL-terminated).
 * @param data5     5-bit values (each in range [0,31]).
 * @param data5len  Number of 5-bit symbols.
 * @param use_m     0 = Bech32 (M=1), 1 = Bech32m (M=0x2BC830A3).
 * @param dst       Output buffer; at minimum hrp_len+1+data5len+6+1 bytes.
 * @param dstcap    Capacity of dst.
 * @return BECH32_OK on success, negative on error.
 */
int bech32_encode(const char *hrp,
                  const uint8_t *data5, size_t data5len,
                  int use_m,
                  char *dst, size_t dstcap);

/**
 * Decode a Bech32 or Bech32m string.
 *
 * @param src        Input string (mixed-case accepted; all-upper or all-lower).
 * @param srclen     Length of input (not counting any NUL).
 * @param hrp_out    Output buffer for the HRP (NUL-terminated).
 * @param hrp_cap    Capacity of hrp_out (at least BECH32_MAX_HRP_LEN+1).
 * @param data5_out  Output buffer for decoded 5-bit symbols.
 * @param data5cap   Capacity of data5_out.
 * @param data5len   Receives the number of 5-bit symbols written.
 * @param use_m_out  Set to 0 if Bech32, 1 if Bech32m.
 * @return BECH32_OK on success, negative on error.
 */
int bech32_decode(const char *src, size_t srclen,
                  char *hrp_out, size_t hrp_cap,
                  uint8_t *data5_out, size_t data5cap, size_t *data5len,
                  int *use_m_out);

/**
 * Convert between bit-group widths (e.g. 8→5 or 5→8).
 *
 * Identical to the reference segwit_addr convertbits().
 *
 * @param out       Output buffer.
 * @param out_len   Receives number of values written.
 * @param out_bits  Target bit-group width (1–8).
 * @param in        Input values.
 * @param in_len    Number of input values.
 * @param in_bits   Source bit-group width (1–8).
 * @param pad       If 1, pad final partial group with zeros; if 0, fail if
 *                  residue remains.
 * @return 0 on success, -1 on overflow/error.
 */
int bech32_convert_bits(uint8_t *out, size_t *out_len,
                        int out_bits,
                        const uint8_t *in, size_t in_len,
                        int in_bits, int pad);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_BECH32_H */
