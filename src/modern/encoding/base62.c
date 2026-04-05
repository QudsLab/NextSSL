/* base62.c — Base62 encoding / decoding
 *
 * Algorithm: big-integer base conversion (standard "divide and modulo"
 * approach applied to the byte array treated as a base-256 number).
 */
#include "base62.h"
#include <string.h>
#include <stdlib.h>

/* ---- alphabet ------------------------------------------------------------ */

static const char s_enc[62] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Reverse lookup: 0xFF = invalid, else index [0,61] */
static const uint8_t s_dec[128] = {
    /*  0- 7 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /*  8-15 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 16-23 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 24-31 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 32-39 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 40-47 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 48-57 */ 0,1,2,3,4,5,6,7,8,9,               /* '0'-'9' */
    /* 58-64 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 65-90 */ 10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
                26,27,28,29,30,31,32,33,34,35,      /* 'A'-'Z' */
    /* 91-96 */ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* 97-122*/ 36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
                52,53,54,55,56,57,58,59,60,61,      /* 'a'-'z' */
    /*123-127*/ 0xFF,0xFF,0xFF,0xFF,0xFF
};

/* ---- helpers ------------------------------------------------------------- */

/* Divide byte-array |p| (big-endian, |len| bytes) by |divisor| in-place.
 * Returns the remainder. */
static uint8_t divmod(uint8_t *p, size_t len, uint8_t divisor)
{
    uint16_t carry = 0;
    for (size_t i = 0; i < len; i++) {
        carry = (carry << 8) | p[i];
        p[i]  = (uint8_t)(carry / divisor);
        carry %= divisor;
    }
    return (uint8_t)carry;
}

/* Multiply byte-array |p| by |factor| and add |addend| in-place.
 * Returns non-zero if overflow (never happens in practice here). */
static int mulmod(uint8_t *p, size_t len, uint8_t factor, uint8_t addend)
{
    uint16_t carry = addend;
    for (size_t i = len; i-- > 0; ) {
        carry += (uint16_t)p[i] * factor;
        p[i]   = (uint8_t)(carry & 0xFF);
        carry >>= 8;
    }
    return (carry != 0); /* overflow */
}

/* ---- public API ---------------------------------------------------------- */

int base62_encode(const uint8_t *src, size_t srclen,
                  char *dst, size_t dstcap,
                  size_t *out_len)
{
    if (!src || !dst || dstcap == 0) return -1;
    if (srclen == 0) {
        dst[0] = '\0';
        if (out_len) *out_len = 0;
        return 0;
    }

    /* Count leading zero bytes — they map to leading '0' characters */
    size_t leading = 0;
    while (leading < srclen && src[leading] == 0) leading++;

    /* Working copy of the input */
    uint8_t *tmp = (uint8_t *)malloc(srclen);
    if (!tmp) return -1;
    memcpy(tmp, src, srclen);

    /* We write characters into a local reverse buffer then flip at the end.
     * Max output length (no NUL): ceil(srclen * log(256)/log(62)) + leading.
     * BASE62_ENCODE_SIZE already accounts for this. */
    size_t maxout = BASE62_ENCODE_SIZE(srclen);
    char *rev = (char *)malloc(maxout);
    if (!rev) { free(tmp); return -1; }

    size_t revlen = 0;

    /* Keep dividing by 62 until the value is zero */
    while (1) {
        /* Check if tmp is all zeros */
        int nonzero = 0;
        for (size_t i = 0; i < srclen; i++) if (tmp[i]) { nonzero = 1; break; }
        if (!nonzero) break;

        uint8_t rem = divmod(tmp, srclen, 62);
        if (revlen >= maxout - 1) { free(tmp); free(rev); return -2; } /* safety */
        rev[revlen++] = s_enc[rem];
    }
    free(tmp);

    /* Add leading '0' characters */
    for (size_t i = 0; i < leading; i++) {
        if (revlen >= maxout - 1) { free(rev); return -2; }
        rev[revlen++] = '0';
    }

    /* Check final length fits in dst */
    if (revlen + 1 > dstcap) { free(rev); return -2; }

    /* Reverse into dst */
    for (size_t i = 0; i < revlen; i++)
        dst[i] = rev[revlen - 1 - i];
    dst[revlen] = '\0';
    free(rev);

    if (out_len) *out_len = revlen;
    return 0;
}

int base62_decode(const char *src, size_t srclen,
                  uint8_t *dst, size_t dstcap,
                  size_t *out_len)
{
    if (!src || !dst || srclen == 0 || dstcap == 0) return -1;

    /* Count leading '0' characters */
    size_t leading = 0;
    while (leading < srclen && src[leading] == '0') leading++;

    /* Working byte array (big-endian accumulator, sized for worst case) */
    /* decoded_len(n) ≈ n * log(62)/log(256) ≤ n * 0.76 + 1 */
    size_t blen = srclen; /* generous upper bound */
    uint8_t *acc = (uint8_t *)calloc(blen, 1);
    if (!acc) return -1;

    for (size_t i = 0; i < srclen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c >= 128 || s_dec[c] == 0xFF) { free(acc); return -3; }
        if (mulmod(acc, blen, 62, s_dec[c])) { free(acc); return -2; }
    }

    /* Skip leading zero bytes produced by the accumulation, restore leading */
    size_t skip = 0;
    while (skip < blen && acc[skip] == 0) skip++;

    size_t decoded = (blen - skip) + leading;
    if (decoded > dstcap) { free(acc); return -2; }

    memset(dst, 0, leading);
    memcpy(dst + leading, acc + skip, blen - skip);
    free(acc);

    if (out_len) *out_len = decoded;
    return 0;
}
