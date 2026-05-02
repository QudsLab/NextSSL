/* base85.c — Base85 encoding (RFC 1924 alphabet)
 *
 * Alphabet (85 printable chars, no whitespace, no NUL):
 *   index 0-9    → '0'-'9'
 *   index 10-35  → 'A'-'Z'
 *   index 36-61  → 'a'-'z'
 *   index 62     → '!'
 *   index 63     → '#'
 *   index 64     → '$'
 *   index 65     → '%'
 *   index 66     → '&'
 *   index 67     → '('
 *   index 68     → ')'
 *   index 69     → '*'
 *   index 70     → '+'
 *   index 71     → '-'
 *   index 72     → ';'
 *   index 73     → '<'
 *   index 74     → '='
 *   index 75     → '>'
 *   index 76     → '?'
 *   index 77     → '@'
 *   index 78     → '^'
 *   index 79     → '_'
 *   index 80     → '`'
 *   index 81     → '{'
 *   index 82     → '|'
 *   index 83     → '}'
 *   index 84     → '~'
 *
 * Padding framing: the two-character suffix '~' + ('~'|'0'|'1'|'2') encodes
 * how many zero-bytes were appended to the last block (0-3).  Decoder
 * strips that many trailing bytes from the decoded output.
 */
#include "base85.h"
#include <string.h>

/* ---- alphabet ------------------------------------------------------------ */

static const char s_enc[85] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~";

/* Reverse map: 0xFF = invalid */
static uint8_t s_dec[128];
static int     s_dec_ready = 0;

static void build_dec(void)
{
    memset(s_dec, 0xFF, sizeof(s_dec));
    for (int i = 0; i < 85; i++)
        s_dec[(unsigned char)s_enc[i]] = (uint8_t)i;
    s_dec_ready = 1;
}

/* ---- public API ---------------------------------------------------------- */

int base85_encode(const uint8_t *src, size_t srclen,
                  char *dst, size_t dstcap,
                  size_t *out_len)
{
    if (!src || !dst) return -1;
    if (dstcap < BASE85_ENCODE_SIZE(srclen)) return -2;

    size_t nblocks  = (srclen + 3) / 4;
    size_t pad      = (srclen % 4 == 0) ? 0 : (4 - srclen % 4);
    size_t pos      = 0;

    for (size_t b = 0; b < nblocks; b++) {
        size_t off = b * 4;
        /* Read 4 bytes, zero-padding the last block if necessary */
        uint32_t v = 0;
        for (int k = 0; k < 4; k++) {
            v <<= 8;
            if (off + (size_t)k < srclen)
                v |= src[off + k];
        }
        /* Convert to 5 base-85 digits (most-significant first) */
        char tmp[5];
        for (int k = 4; k >= 0; k--) {
            tmp[k] = s_enc[v % 85];
            v     /= 85;
        }
        for (int k = 0; k < 5; k++)
            dst[pos++] = tmp[k];
    }

    /* Append padding suffix */
    dst[pos++] = '~';
    dst[pos++] = (pad == 0) ? '~' : (char)('0' + pad - 1);
    dst[pos]   = '\0';

    if (out_len) *out_len = pos;
    return 0;
}

int base85_decode(const char *src, size_t srclen,
                  uint8_t *dst, size_t dstcap,
                  size_t *out_len)
{
    if (!src || !dst || srclen < 2) return -1;
    if (!s_dec_ready) build_dec();

    /* Locate and validate the 2-byte suffix '~' + ('~'|'0'|'1'|'2') */
    if (src[srclen - 2] != '~') return -4;
    char      suffix = src[srclen - 1];
    size_t    pad;
    if (suffix == '~')      pad = 0;
    else if (suffix == '0') pad = 1;
    else if (suffix == '1') pad = 2;
    else if (suffix == '2') pad = 3;
    else                    return -4;

    size_t data_chars = srclen - 2;
    if (data_chars % 5 != 0) return -3; /* must be 5-char aligned */

    size_t nblocks   = data_chars / 5;
    size_t raw_bytes = nblocks * 4;
    if (raw_bytes < pad) return -4;
    size_t decoded   = raw_bytes - pad;

    if (decoded > dstcap) return -2;

    for (size_t b = 0; b < nblocks; b++) {
        const char *p = src + b * 5;
        uint32_t v = 0;
        for (int k = 0; k < 5; k++) {
            unsigned char c = (unsigned char)p[k];
            if (c >= 128 || s_dec[c] == 0xFF) return -3;
            v = v * 85 + s_dec[c];
        }
        /* Write 4 bytes big-endian */
        uint8_t blk[4] = {
            (uint8_t)(v >> 24),
            (uint8_t)(v >> 16),
            (uint8_t)(v >>  8),
            (uint8_t)(v      )
        };
        size_t bytes_to_write = (b == nblocks - 1) ? (4 - pad) : 4;
        for (size_t k = 0; k < bytes_to_write; k++)
            dst[b * 4 + k] = blk[k];
    }

    if (out_len) *out_len = decoded;
    return 0;
}
