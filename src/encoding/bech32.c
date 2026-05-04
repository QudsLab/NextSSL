/* bech32.c — Bech32 and Bech32m encoding / decoding
 *
 * Reference: BIP 0173 (Bech32) and BIP 0350 (Bech32m)
 * Checksum constants:
 *   Bech32  (use_m=0): M = 0x00000001
 *   Bech32m (use_m=1): M = 0x2BC830A3
 *
 * The GF(2^32) checksum polynomial is
 *   x^32 + x^29 + x^24 + x^13 + x^9 + x^5 + x^1 + 1  (BIP 0173 Appendix A)
 */
#include "bech32.h"
#include <string.h>
#include <ctype.h>

/* ---- constants ----------------------------------------------------------- */

#define BECH32_M  UINT32_C(0x00000001)
#define BECH32M_M UINT32_C(0x2BC830A3)

static const char s_charset[]  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int8_t s_charmap[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30, 7, 5,-1,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1
};

/* ---- checksum ------------------------------------------------------------ */

static uint32_t polymod(const uint8_t *v, size_t vlen)
{
    static const uint32_t gen[5] = {
        0x3B6A57B2u, 0x26508E6Du, 0x1EA119FAu, 0x3D4233DDu, 0x2A1462B3u
    };
    uint32_t c = 1;
    for (size_t i = 0; i < vlen; i++) {
        uint8_t c0 = (uint8_t)(c >> 25);
        c = ((c & 0x1FFFFFFu) << 5) ^ v[i];
        for (int j = 0; j < 5; j++) {
            if ((c0 >> j) & 1) c ^= gen[j];
        }
    }
    return c;
}

/* Build the polymod input for an hrp + data array. */
static uint32_t compute_checksum(const char *hrp, size_t hrplen,
                                  const uint8_t *data, size_t datalen)
{
    /* hrp size prefix + 0 separator + data + 6 zeroes */
    size_t buflen = hrplen + 1 + hrplen + datalen + 6;
    /* Max possible: 2*83 + 1 + 64 + 6 = 237.  Use a safe fixed size that
     * covers any valid bech32 input (total encoded length <= 90, data <= 64). */
    uint8_t buf[2 * 83 + 1 + 64 + 6 + 8]; /* 244 bytes — always sufficient */
    if (buflen > sizeof(buf)) return 0; /* should never happen given our limits */

    size_t pos = 0;
    /* High 5 bits of each HRP character */
    for (size_t i = 0; i < hrplen; i++) buf[pos++] = (uint8_t)(hrp[i] >> 5);
    /* Separator */
    buf[pos++] = 0;
    /* Low 5 bits of each HRP character */
    for (size_t i = 0; i < hrplen; i++) buf[pos++] = (uint8_t)(hrp[i] & 0x1F);
    /* Data */
    for (size_t i = 0; i < datalen; i++) buf[pos++] = data[i];
    /* Six zero placeholders */
    for (int i = 0; i < 6; i++) buf[pos++] = 0;

    return polymod(buf, pos);
}

/* ---- public API ---------------------------------------------------------- */

int bech32_encode(const char *hrp,
                  const uint8_t *data5, size_t data5len,
                  int use_m,
                  char *dst, size_t dstcap)
{
    if (!hrp || !data5 || !dst) return BECH32_ERR_INPUT;

    size_t hrplen = strlen(hrp);
    if (hrplen == 0 || hrplen > BECH32_MAX_HRP_LEN) return BECH32_ERR_HRP;

    /* Validate HRP (printable ASCII, but the spec mandates lowercase */
    for (size_t i = 0; i < hrplen; i++) {
        unsigned char c = (unsigned char)hrp[i];
        if (c < 33 || c > 126) return BECH32_ERR_HRP;
        if (isupper(c)) return BECH32_ERR_HRP;
    }

    /* Validate data5 values */
    for (size_t i = 0; i < data5len; i++) {
        if (data5[i] > 31) return BECH32_ERR_INPUT;
    }

    /* Total length: hrp + '1' + data5len + 6 checksum  (must be ≤ 90) */
    size_t total = hrplen + 1 + data5len + 6;
    if (total > BECH32_MAX_TOTAL_LEN) return BECH32_ERR_LENGTH;
    if (total + 1 > dstcap)           return BECH32_ERR_BUFFER;

    uint32_t M  = use_m ? BECH32M_M : BECH32_M;
    uint32_t cs = compute_checksum(hrp, hrplen, data5, data5len) ^ M;

    char *p = dst;
    /* HRP */
    for (size_t i = 0; i < hrplen; i++) *p++ = (char)tolower((unsigned char)hrp[i]);
    /* Separator */
    *p++ = '1';
    /* Data */
    for (size_t i = 0; i < data5len; i++) *p++ = s_charset[data5[i]];
    /* Checksum (6 symbols) */
    for (int i = 5; i >= 0; i--) {
        *p++ = s_charset[(cs >> (5 * i)) & 0x1F];
    }
    *p = '\0';

    return BECH32_OK;
}

int bech32_decode(const char *src, size_t srclen,
                  char *hrp_out, size_t hrp_cap,
                  uint8_t *data5_out, size_t data5cap, size_t *data5len,
                  int *use_m_out)
{
    if (!src || srclen == 0 || !hrp_out || !data5_out || !data5len || !use_m_out)
        return BECH32_ERR_INPUT;

    if (srclen > BECH32_MAX_TOTAL_LEN) return BECH32_ERR_LENGTH;

    /* BIP 0173: must not be all-uppercase mixed with lowercase */
    int has_upper = 0, has_lower = 0;
    for (size_t i = 0; i < srclen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c < 33 || c > 126) return BECH32_ERR_CHAR;
        if (isupper(c)) has_upper = 1;
        if (islower(c)) has_lower = 1;
    }
    if (has_upper && has_lower) return BECH32_ERR_CHAR;

    /* Find last '1' separator */
    int sep = -1;
    for (int i = (int)srclen - 1; i >= 0; i--) {
        if (src[i] == '1') { sep = i; break; }
    }
    if (sep < 1) return BECH32_ERR_SEPARATOR; /* HRP must be ≥1 char */
    /* Data part must hold at least 6 checksum chars */
    if ((int)srclen - sep - 1 < 6) return BECH32_ERR_SEPARATOR;

    size_t hrplen  = (size_t)sep;
    size_t datalen = srclen - hrplen - 1; /* includes 6 checksum chars */

    if (hrplen + 1 > hrp_cap)       return BECH32_ERR_BUFFER;
    if (datalen > data5cap + 6)      return BECH32_ERR_BUFFER;

    /* Copy HRP (lowercased) */
    for (size_t i = 0; i < hrplen; i++)
        hrp_out[i] = (char)tolower((unsigned char)src[i]);
    hrp_out[hrplen] = '\0';

    /* Decode data symbols */
    uint8_t dec[BECH32_MAX_TOTAL_LEN];
    for (size_t i = 0; i < datalen; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)src[hrplen + 1 + i]);
        if (c >= 128 || s_charmap[c] == -1) return BECH32_ERR_CHAR;
        dec[i] = (uint8_t)s_charmap[c];
    }

    /* Verify checksum against both Bech32 and Bech32m constants */
    size_t payload_len = datalen - 6;
    uint32_t chk = compute_checksum(hrp_out, hrplen, dec, datalen);
    if      (chk == BECH32_M)  *use_m_out = 0;
    else if (chk == BECH32M_M) *use_m_out = 1;
    else return BECH32_ERR_CHECKSUM;

    if (payload_len > data5cap) return BECH32_ERR_BUFFER;
    memcpy(data5_out, dec, payload_len);
    *data5len = payload_len;

    return BECH32_OK;
}

int bech32_convert_bits(uint8_t *out, size_t *out_len,
                        int out_bits,
                        const uint8_t *in, size_t in_len,
                        int in_bits, int pad)
{
    if (!out || !out_len || !in) return -1;

    uint32_t acc   = 0;
    int      bits  = 0;
    size_t   pos   = 0;
    uint32_t maxv  = (uint32_t)((1 << out_bits) - 1);
    uint32_t maxacc= (uint32_t)((1 << (in_bits + out_bits - 1)) - 1);

    for (size_t i = 0; i < in_len; i++) {
        uint32_t value = in[i];
        if (value >> in_bits) return -1; /* value out of range */
        acc  = ((acc << in_bits) | value) & maxacc;
        bits += in_bits;
        while (bits >= out_bits) {
            bits -= out_bits;
            out[pos++] = (uint8_t)((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) out[pos++] = (uint8_t)((acc << (out_bits - bits)) & maxv);
    } else if (bits >= in_bits || ((acc << (out_bits - bits)) & maxv)) {
        return -1; /* non-zero padding on decode */
    }

    *out_len = pos;
    return 0;
}
