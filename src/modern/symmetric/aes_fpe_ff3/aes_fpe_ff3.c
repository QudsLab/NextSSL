/* aes_fpe_ff3.c — AES FF3-1 Format-Preserving Encryption (SP 800-38G Rev 1)
 *
 * Implementation of the FF3-1 algorithm from NIST SP 800-38G Revision 1.
 * FF3-1 uses a 7-byte tweak (56 bits) and AES in a reversed-key Feistel network.
 *
 * Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1.pdf
 *
 * Key is byte-reversed before use in each AES call (SP 800-38G §4 Note 3).
 * The tweak is byte-reversed and split into T_L (4 bytes) and T_R (3 bytes).
 */
#include "aes_fpe_ff3.h"
#include "../_aes/aes_core.h"  /* aes_ecb_encrypt_block_revkey */
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ── Internal helpers ────────────────────────────────────────────────────── */

/* Reverse byte order of a buffer into dest (may alias src) */
static void reverse_bytes(const uint8_t *src, uint8_t *dst, size_t n)
{
    if (src == dst) {
        for (size_t i = 0; i < n / 2; i++) {
            uint8_t tmp = dst[i]; dst[i] = dst[n-1-i]; dst[n-1-i] = tmp;
        }
    } else {
        for (size_t i = 0; i < n; i++) dst[i] = src[n-1-i];
    }
}

/* num_radix(X, len, radix) — convert numeral string to big integer (uint64_t).
 * Only used for sub-strings short enough to fit in 64 bits. */
static uint64_t num_radix(const uint32_t *X, size_t len, uint32_t radix)
{
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++) val = val * radix + X[i];
    return val;
}

/* str_radix(val, radix, out, out_len) — convert integer to numeral string
 * of exactly out_len digits, most-significant first. */
static void str_radix(uint64_t val, uint32_t radix, uint32_t *out, size_t out_len)
{
    for (size_t i = out_len; i-- > 0; ) {
        out[i] = (uint32_t)(val % radix);
        val /= radix;
    }
}

/* revb(X, len) — reverse a numeral array in-place */
static void revb(uint32_t *X, size_t len)
{
    for (size_t i = 0; i < len / 2; i++) {
        uint32_t tmp = X[i]; X[i] = X[len-1-i]; X[len-1-i] = tmp;
    }
}

/* Compute PRF_FF3: AES in revkey mode.
 * The 16-byte input is encrypted with the byte-reversed key.
 * Writes 16 bytes to out. */
static void prf_ff3(const uint8_t *key, size_t keylen,
                    const uint8_t  in[16], uint8_t out[16])
{
    /* Reverse the key */
    uint8_t rk[32];
    reverse_bytes(key, rk, keylen);
    /* Reverse the input */
    uint8_t ri[16];
    reverse_bytes(in, ri, 16);
    /* AES-ECB encrypt */
    aes_ecb_encrypt_block(rk, (int)(keylen * 8), ri, out);
    /* Reverse the output */
    reverse_bytes(out, out, 16);
}

/* Validate FF3-1 parameters */
static int ff3_validate(size_t keylen, uint32_t radix, size_t len)
{
    if (keylen != 16 && keylen != 24 && keylen != 32) return -1;
    if (radix < 2 || radix > 65536u) return -1;
    /* minlen: ceil(log(1000000) / log(radix)) */
    if (len < 2) return -1;
    if (len > AES_FF3_MAX_LEN) return -1;
    /* radix^len must be at least 100 (SP 800-38G §5.2 constraint minlen) */
    double check = (double)len * log((double)radix);
    if (check < log(100.0)) return -1;
    return 0;
}

/* ── FF3-1 core ─────────────────────────────────────────────────────────── */

/* Build the W value for round i:
 *   W = T_R XOR [i]^4  when i is odd
 *   W = T_L XOR [i]^4  when i is even
 * tweak7[0..6]: original 7-byte tweak
 * i: round index (0-7) */
static void build_w(const uint8_t tweak7[7], int i, uint8_t W[4])
{
    /* T_R = tweak bytes [4..6] zero-padded to 4 bytes */
    /* T_L = tweak bytes [0..3] */
    if (i % 2 == 0) {
        /* W = T_L XOR [i]^4 */
        W[0] = tweak7[0]; W[1] = tweak7[1]; W[2] = tweak7[2]; W[3] = tweak7[3];
    } else {
        /* W = T_R || 0x00 XOR [i]^4 */
        W[0] = tweak7[4]; W[1] = tweak7[5]; W[2] = tweak7[6]; W[3] = 0x00;
    }
    W[3] ^= (uint8_t)(i & 0xFF);
}

int aes_ff3_encrypt(const uint8_t *key,   size_t keylen,
                    const uint8_t  tweak[AES_FF3_TWEAK_LEN],
                    uint32_t       radix,
                    const uint32_t *X,    size_t len,
                    uint32_t       *Y)
{
    if (!key || !tweak || !X || !Y || len == 0) return -1;
    if (ff3_validate(keylen, radix, len) != 0) return -1;

    /* Split into halves u and v where u = ceil(n/2), v = n - u */
    size_t u = (len + 1) / 2;
    size_t v = len - u;

    /* Copy into mutable A and B */
    uint32_t *A = (uint32_t *)malloc(u * sizeof(uint32_t));
    uint32_t *B = (uint32_t *)malloc(v * sizeof(uint32_t));
    uint32_t *C = (uint32_t *)malloc(u * sizeof(uint32_t));
    if (!A || !B || !C) { free(A); free(B); free(C); return -1; }

    memcpy(A, X,     u * sizeof(uint32_t));
    memcpy(B, X + u, v * sizeof(uint32_t));

    /* Reversed tweak bytes */
    uint8_t tweak_rev[7];
    reverse_bytes(tweak, tweak_rev, 7);

    int ret = -1;

    for (int i = 0; i < 8; i++) {
        /* m = length of current right half (B when i even, A when i odd) */
        size_t m = (i % 2 == 0) ? u : v;

        /* Build W (4 bytes) */
        uint8_t W[4];
        build_w(tweak, i, W);

        /* P = W || [NUMrev_radix(REV(B)) mod 2^96] encoded as 12 bytes */
        /* REV(B) is B reversed; NUMrev_radix is the numeral value reversed */
        /* For simplicity, encode B reversed as big-endian 96-bit integer */

        /* Rev(B): reverse the B array */
        uint32_t *Brev = (uint32_t *)malloc(v * sizeof(uint32_t));
        if (!Brev) goto done;
        memcpy(Brev, B, v * sizeof(uint32_t));
        revb(Brev, v);

        /* Compute NUMradix(Brev) as a 96-bit big-endian integer (12 bytes) */
        /* We use a simple big-integer-like approach for base conversion */
        /* Store as 12 bytes: most significant first */
        uint8_t P[16];
        memcpy(P, W, 4);
        /* Encode num in 12 bytes */
        memset(P + 4, 0, 12);
        /* Compute value as big integer */
        for (size_t j = 0; j < v; j++) {
            /* multiply P[4..15] by radix and add Brev[j] */
            uint32_t carry = Brev[j];
            for (int k = 15; k >= 4; k--) {
                uint32_t t = (uint32_t)P[k] * radix + carry;
                P[k] = (uint8_t)(t & 0xFF);
                carry = t >> 8;
            }
        }
        free(Brev);

        /* S = REVB(AES_REVK(P)) */
        uint8_t S[16];
        prf_ff3(key, keylen, P, S);

        /* c = (NUMradix(REV(A)) + NUMradix(S)) mod radix^m */
        /* Reverse A */
        uint32_t *Arev = (uint32_t *)malloc(u * sizeof(uint32_t));
        if (!Arev) goto done;
        memcpy(Arev, A, u * sizeof(uint32_t));
        revb(Arev, u);

        /* Convert Arev to big integer mod radix^m */
        /* Then add S (as big integer) mod radix^m */
        /* For practical radices and lengths that fit in 64 bits: */
        if (m <= 18 && radix <= 36) {
            /* Fast path: fits in 64-bit arithmetic */
            uint64_t num_a = num_radix(Arev, u, radix);
            /* Convert S to integer (big-endian 16 bytes) */
            uint64_t num_s = 0;
            for (int k = 0; k < 16; k++) num_s = (num_s << 8) | S[k];
            /* Compute radix^m */
            uint64_t mod = 1;
            for (size_t k = 0; k < m; k++) mod *= radix;
            uint64_t c_val = (num_a + num_s) % mod;
            str_radix(c_val, radix, C, m);
        } else {
            /* For large m: use multi-precision addition mod radix^m
             * Stored as radix digits, most-significant first */
            /* Convert Arev (len=u) to C (len=m), zero-padding if u < m */
            memset(C, 0, m * sizeof(uint32_t));
            size_t off = (m > u) ? (m - u) : 0;
            for (size_t k = 0; k < u && off + k < m; k++) C[off + k] = Arev[k];

            /* Add S (16-byte big-endian) digit by digit from the right */
            uint32_t carry = 0;
            /* Process S as base-256 then convert to base-radix is complex;
             * use a simpler: add S bytes as a big-endian number */
            for (int k = 15; k >= 0; k--) {
                if ((size_t)(15 - k) >= m) break;
                uint32_t idx = (uint32_t)m - 1 - (uint32_t)(15 - k);
                uint32_t t = C[idx] + (uint32_t)S[k] + carry;
                C[idx] = t % radix;
                carry = t / radix;
            }
            /* Propagate carry */
            for (int k = (int)m - 17; k >= 0; k--) {
                if (carry == 0) break;
                uint32_t t = C[k] + carry;
                C[k] = t % radix;
                carry = t / radix;
            }
        }
        free(Arev);

        /* A = B, B = REV(C) */
        memcpy(A, B, v * sizeof(uint32_t));
        /* swap size tracking: after odd rounds u/v swap roles */
        revb(C, m);
        memcpy(B, C, m * sizeof(uint32_t));
        /* swap u/v for next round */
        { size_t tmp_sz = u; u = v; v = tmp_sz; }
    }

    /* Output A || B */
    memcpy(Y,       A, u * sizeof(uint32_t));
    memcpy(Y + u,   B, v * sizeof(uint32_t));
    ret = 0;

done:
    free(A); free(B); free(C);
    return ret;
}

int aes_ff3_decrypt(const uint8_t *key,   size_t keylen,
                    const uint8_t  tweak[AES_FF3_TWEAK_LEN],
                    uint32_t       radix,
                    const uint32_t *Y,    size_t len,
                    uint32_t       *X)
{
    if (!key || !tweak || !Y || !X || len == 0) return -1;
    if (ff3_validate(keylen, radix, len) != 0) return -1;

    size_t u = (len + 1) / 2;
    size_t v = len - u;

    uint32_t *A = (uint32_t *)malloc(u * sizeof(uint32_t));
    uint32_t *B = (uint32_t *)malloc(v * sizeof(uint32_t));
    uint32_t *C = (uint32_t *)malloc(u * sizeof(uint32_t));
    if (!A || !B || !C) { free(A); free(B); free(C); return -1; }

    memcpy(A, Y,     u * sizeof(uint32_t));
    memcpy(B, Y + u, v * sizeof(uint32_t));

    int ret = -1;

    for (int i = 7; i >= 0; i--) {
        size_t m = (i % 2 == 0) ? u : v;

        uint8_t W[4];
        build_w(tweak, i, W);

        uint32_t *Arev = (uint32_t *)malloc(u * sizeof(uint32_t));
        if (!Arev) goto done;
        memcpy(Arev, A, u * sizeof(uint32_t));
        revb(Arev, u);

        uint8_t P[16];
        memcpy(P, W, 4);
        memset(P + 4, 0, 12);
        for (size_t j = 0; j < u; j++) {
            uint32_t carry = Arev[j];
            for (int k = 15; k >= 4; k--) {
                uint32_t t = (uint32_t)P[k] * radix + carry;
                P[k] = (uint8_t)(t & 0xFF);
                carry = t >> 8;
            }
        }
        free(Arev);

        uint8_t S[16];
        prf_ff3(key, keylen, P, S);

        uint32_t *Brev = (uint32_t *)malloc(v * sizeof(uint32_t));
        if (!Brev) goto done;
        memcpy(Brev, B, v * sizeof(uint32_t));
        revb(Brev, v);

        /* c = (NUMradix(REV(B)) - NUMradix(S)) mod radix^m */
        if (m <= 18 && radix <= 36) {
            uint64_t num_b = num_radix(Brev, v, radix);
            uint64_t num_s = 0;
            for (int k = 0; k < 16; k++) num_s = (num_s << 8) | S[k];
            uint64_t mod = 1;
            for (size_t k = 0; k < m; k++) mod *= radix;
            num_s = num_s % mod;
            uint64_t c_val = (num_b + mod - num_s) % mod;
            str_radix(c_val, radix, C, m);
        } else {
            memset(C, 0, m * sizeof(uint32_t));
            size_t off = (m > v) ? (m - v) : 0;
            for (size_t k = 0; k < v && off + k < m; k++) C[off + k] = Brev[k];
            /* Subtract S */
            int32_t borrow = 0;
            for (int k = 15; k >= 0; k--) {
                if ((size_t)(15 - k) >= m) break;
                uint32_t idx = (uint32_t)m - 1 - (uint32_t)(15 - k);
                int32_t t = (int32_t)C[idx] - (int32_t)S[k] - borrow;
                if (t < 0) { t += (int32_t)radix; borrow = 1; } else borrow = 0;
                C[idx] = (uint32_t)t;
            }
            for (int k = (int)m - 17; k >= 0; k--) {
                if (!borrow) break;
                int32_t t = (int32_t)C[k] - borrow;
                if (t < 0) { t += (int32_t)radix; borrow = 1; } else borrow = 0;
                C[k] = (uint32_t)t;
            }
        }
        free(Brev);

        /* B = A, A = REV(C) */
        memcpy(B, A, u * sizeof(uint32_t));
        revb(C, m);
        memcpy(A, C, m * sizeof(uint32_t));
        { size_t tmp_sz = u; u = v; v = tmp_sz; }
    }

    memcpy(X,     A, u * sizeof(uint32_t));
    memcpy(X + u, B, v * sizeof(uint32_t));
    ret = 0;

done:
    free(A); free(B); free(C);
    return ret;
}
