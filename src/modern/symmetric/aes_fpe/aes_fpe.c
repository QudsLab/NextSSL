#include "aes_fpe.h"
#include "aes_internal.h"
#include <stdlib.h>
#include <limits.h>

/* Helper macros for FPE configuration */
#ifndef CUSTOM_ALPHABET
#define CUSTOM_ALPHABET 0
#endif

#include "aes_fpe_alphabets.h"

#if ALPHABET_IS_NON_ASCII
typedef wchar_t  alpha_t;
#else
typedef char     alpha_t;
#endif

#if RADIX <= 1 + UCHAR_MAX
typedef unsigned char  radix_t;
#else
typedef unsigned short radix_t;
#endif

/* Forward declarations */
static void FF1_cipher(const uint8_t* key, const char mode, const TWEAK_PARAMS_DEF, const size_t len, radix_t* X);
#if FF_X == 3
static void FF3_cipher(const uint8_t* key, const char mode, const TWEAK_PARAMS_DEF, const size_t len, radix_t* X);
#endif

#if FF_X == 3
#define FPE_PERMUTE    FF3_cipher
#define TWEAK_AGRS     tweak
#else
#define FPE_PERMUTE    FF1_cipher
#define TWEAK_AGRS     tweak, tweakLen

static size_t b1;

static void numRadix( const radix_t* s, size_t len, uint8_t* num, size_t bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {
        size_t i, y = *s++;
        for (i = bytes; i--; y >>= 8)
        {
            y += num[i] * RADIX;
            num[i] = (uint8_t) y;
        }
    }
}

static void strRadix( const uint8_t* num, size_t bytes, radix_t* s, size_t len )
{
    memset( s, 0, sizeof (radix_t) * len );
    while (bytes--)
    {
        size_t i, x = *num++;
        for (i = len; i--; x /= RADIX)
        {
            x += s[i] << 8;
            s[i] = x % RADIX;
        }
    }
}

static void addRadix( const radix_t* x, const size_t len, radix_t* y )
{
    size_t i, a = 0;
    for (i = len; i--; a /= RADIX)
    {
        a += y[i] + x[i];
        y[i] = a % RADIX;
    }
}

static void subRadix( const radix_t* x, const size_t len, radix_t* y )
{
    size_t i, s = 1;
    for (i = len; i--; s /= RADIX)
    {
        s += RADIX - 1 + y[i] - x[i];
        y[i] = s % RADIX;
    }
}

static void FF1round( const uint8_t i, const block_t P,
                      const size_t u, const size_t v, radix_t* C )
{
    block_t R = { 0 };
    uint8_t* num = (uint8_t*) &C[u];
    size_t k = b1 % sizeof R, ext = (i & 1) * u;

    numRadix( C - v - ext, v, num, b1 );
    num[-1] = i;
    memcpy( R + LAST - k, num - 1, k + 1 );

    xMac( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    xMac( num + k, b1 - k, R, &rijndaelEncrypt, R );

    memcpy( num, R, sizeof R );
    k = (b1 + 3L) / sizeof R;

    for (ext = 0; k; ext = k--)
    {
        xorBEint( R, ext ^ k, LAST );
        rijndaelEncrypt( R, num + k * sizeof R );
    }
    strRadix( num, (b1 + 7) & ~3L, C, u );
}

static void FF1_cipher( const uint8_t* key, const char mode,
                        const TWEAK_PARAMS_DEF, const size_t len, radix_t* X )
{
    size_t u = (len + !mode) / 2, t = tweakLen;
    radix_t* xC = X + len;
    block_t P = { 1, 2, 1, RADIX >> 16, RADIX >> 8 & 0xFF, RADIX & 0xFF, 10 };
    uint8_t i = t % sizeof P + b1 % sizeof P < BLOCKSIZE ? t % sizeof P : 0;

    AES_setkey( key );

    P[7] ^= len / 2;
    xorBEint( P, len, 11 );
    xorBEint( P, t, LAST );
    rijndaelEncrypt( P, P );
    xMac( tweak, t - i, P, &rijndaelEncrypt, P );

    while (i)
    {
        P[--i] ^= tweak[--t];
    }
    for (; i < 10 * mode; ++i, u = t)
    {
        FF1round( i, P, u, t = len - u, xC );
        addRadix( xC, u, X + (i & 1) * t );
    }
    for (i ^= 10; i-- != 0x00; u = t)
    {
        FF1round( i, P, u, t = len - u, xC );
        subRadix( xC, u, X + (i & 1) * t );
    }
}
#endif /* FF1 */

#if FF_X == 3
/* ── FF3-1 implementation (NIST SP 800-38G Rev.1) ────────────────────────
 *
 * Key size:  32 bytes (AES-256 reversed for decryption direction).
 * Tweak:      7 bytes.  Internally split as T_L = tweak[0..3] and
 *             T_R = tweak[3..6] (tweak[3] is shared, zero-extended).
 * Radix:      defined by RADIX / ALPHABET macros above.
 * Length:     MINLEN..MAXLEN symbols.
 * Rounds:     8 (i = 0..7).
 *
 * Round function W = REV(REVK-AES-ECB(REV(B_half) XOR W_key))
 * where REVK means AES keyed with the byte-reversed key.
 */

/* Reverse bytes of `len` bytes in-place */
static void ff3_rev(uint8_t *buf, size_t len)
{
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        uint8_t t = buf[i]; buf[i] = buf[j]; buf[j] = t;
    }
}

/* Reverse bytes of src into dst (src and dst must not overlap) */
static void ff3_revcp(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++) dst[i] = src[len - 1 - i];
}

/*
 * numFF3 / strFF3: same big-endian conversion as numRadix/strRadix but
 * operating on u = u_len symbols.
 */
static void numFF3(const radix_t *s, size_t len, uint8_t *num, size_t bytes)
{
    memset(num, 0, bytes);
    while (len--) {
        size_t i, y = *s++;
        for (i = bytes; i--; y >>= 8) {
            y += num[i] * RADIX;
            num[i] = (uint8_t)y;
        }
    }
}

static void strFF3(const uint8_t *num, size_t bytes, radix_t *s, size_t len)
{
    memset(s, 0, sizeof(radix_t) * len);
    while (bytes--) {
        size_t i, x = *num++;
        for (i = len; i--; x /= RADIX) {
            x += (size_t)s[i] << 8;
            s[i] = (radix_t)(x % RADIX);
        }
    }
}

static void addFF3(const radix_t *x, size_t len, radix_t *y, size_t mod)
{
    size_t i, a = 0;
    for (i = len; i--; a /= mod) {
        a += (size_t)y[i] + x[i];
        y[i] = (radix_t)(a % mod);
    }
}

static void subFF3(const radix_t *x, size_t len, radix_t *y, size_t mod)
{
    size_t i, s = 1;
    for (i = len; i--; s /= mod) {
        s += mod - 1 + (size_t)y[i] - x[i];
        y[i] = (radix_t)(s % mod);
    }
}

static void FF3_cipher(const uint8_t *key, const char mode,
                       const TWEAK_PARAMS_DEF, const size_t len, radix_t *X)
{
    /* Split plaintext into A = X[0..u-1], B = X[u..len-1] */
    size_t u = (len + 1) / 2;  /* ceil */
    size_t v = len - u;
    radix_t *A = X;
    radix_t *B = X + u;

    /* Key sizes: for FF3-1 key must be 32 bytes (AES-256).
     * The reversed key is used for one direction of the Feistel. */
    uint8_t revKey[KEYSIZE];
    ff3_revcp(revKey, key, KEYSIZE);

    /* Tweak split: T_L = tweak[0..3] (4 bytes), T_R = tweak[4..6] (3 bytes, zero-pad) */
    uint8_t T_L[4], T_R[4];
    memcpy(T_L, tweak, 4);
    T_R[0] = tweak[4]; T_R[1] = tweak[5]; T_R[2] = tweak[6]; T_R[3] = 0x00;

    /* byte length of a half: m bytes can hold ceil(v * log2(RADIX) / 8) */
    size_t m_u = (size_t)((u * LOGRDX + 7) / 8);
    size_t m_v = (size_t)((v * LOGRDX + 7) / 8);
    if (m_u > 12) m_u = 12;
    if (m_v > 12) m_v = 12;

    /* Allocate scratch buffers for NUMradix outputs (max 12 bytes each) */
    uint8_t numA[12], numB[12];
    block_t W;

    /* 8 rounds forward (encrypt) or reverse (decrypt) */
    for (int round = 0; round < 8; round++) {
        int i = mode ? round : (7 - round);

        /* Determine which half is updated this round (A for even, B for odd) */
        int update_A = (i & 1) == 0;
        radix_t *upd = update_A ? A : B;   /* half to update */
        radix_t *src = update_A ? B : A;   /* half used as input to PRF */
        size_t   m   = update_A ? m_u : m_v;
        size_t   half_len = update_A ? u   : v;
        size_t   src_len  = update_A ? v   : u;

        /* Build W = REV(NUMradix(REV(src_half))) XOR tweak_block */
        size_t src_m = update_A ? m_v : m_u;
        numFF3(src, src_len, numB, src_m);
        ff3_rev(numB, src_m);

        /* Pad numB into the low bytes of a 16-byte block */
        memset(W, 0, BLOCKSIZE);
        if (src_m <= BLOCKSIZE) memcpy(W + BLOCKSIZE - src_m, numB, src_m);

        /* XOR with tweak part: even rounds use T_R, odd rounds use T_L */
        /* XOR round counter into tweak byte */
        uint8_t tw[4];
        if ((i & 1) == 0) {
            memcpy(tw, T_R, 4); tw[3] ^= (uint8_t)i;
        } else {
            memcpy(tw, T_L, 4); tw[3] ^= (uint8_t)i;
        }
        W[0] ^= tw[0]; W[1] ^= tw[1]; W[2] ^= tw[2]; W[3] ^= tw[3];

        /* AES with reversed key, then reverse the output block */
        AES_setkey(revKey);
        rijndaelEncrypt(W, W);
        ff3_rev(W, BLOCKSIZE);

        /* c = STRm(NUMradix(REV(upd_half)) + NUMradix(W)) mod radix^half_len */
        numFF3(upd, half_len, numA, m);
        ff3_rev(numA, m);

        /* c = (NUMradix(numA) + NUMradix(W[0..m-1])) mod radix^half_len
         * We do this as strFF3(W, m, temp, half_len), then addFF3 */
        radix_t *c = (radix_t *)malloc(half_len * sizeof(radix_t));
        if (!c) return;  /* allocation failure — leave state unchanged */

        strFF3(W, m, c, half_len);
        /* addFF3 / subFF3 on numA-as-symbols: convert numA back to symbols */
        radix_t *upd_sym = (radix_t *)malloc(half_len * sizeof(radix_t));
        if (!upd_sym) { free(c); return; }
        strFF3(numA, m, upd_sym, half_len);

        if (mode) {
            addFF3(upd_sym, half_len, c, RADIX);
        } else {
            subFF3(upd_sym, half_len, c, RADIX);
            /* For decrypt: c is old A', so result = c used as new upd value */
        }

        memcpy(upd, c, half_len * sizeof(radix_t));
        free(upd_sym);
        free(c);

        /* Swap A and B for next round (Feistel swap) */
        radix_t *tmp_ptr = A; A = B; B = tmp_ptr;
        size_t   tmp_sz  = u; u = v; v = tmp_sz;
        /* Recompute split pointers relative to X */
        (void)tmp_ptr; (void)tmp_sz;
    }

    /* After 8 rounds the Feistel may have swapped A/B an even number of
     * times (8 swaps → back to original positions). Output is already in X. */
    AES_setkey(key);   /* restore key schedule to original key */
    AES_burn();
}
#endif /* FF_X == 3 */

static char FPE_cipher( const uint8_t* key, const char mode, const TWEAK_PARAMS_DEF,
                        const void* input, const size_t dataSize, void* output )
{
    size_t v = (dataSize + 1) / 2;
    size_t n = (dataSize + v) * sizeof (radix_t);
    alpha_t const* alpha = ALPHABET;
    alpha_t* y = output;
    radix_t* index;

    if (dataSize < MINLEN)  return 'l';
#if FF_X == 3
    if (dataSize > MAXLEN)  return 'L';
    v *= sizeof (radix_t);
    n += v < KEYSIZE ? KEYSIZE - v : 0;
#else
    b1 = (size_t) (LOGRDX * v + 8 - 1e-14) / 8;
    n += (b1 + 4 + LAST) & ~LAST;
#endif

    if ((index = malloc( n )) == NULL)
    {
        return 'm';
    }
    for (n = 0; n < dataSize; ++n)
    {
        const alpha_t *ch = (alpha_t*) input + n;
        for (v = 0x0; *ch != alpha[v]; )
        {
            if (++v == RADIX)
            {
                free( index );
                return 'C';
            }
        }
        *(index + n) = (radix_t) v;
    }

    FPE_PERMUTE( key, mode, TWEAK_AGRS, n, index );
    AES_burn();

    for (y[n] = 0; n--; )
    {
        y[n] = alpha[index[n]];
    }
    free( index );
    return 0;
}

char AES_FPE_encrypt( const uint8_t* key, const TWEAK_PARAMS_DEF,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    char result = FPE_cipher( key, 1, TWEAK_AGRS, pntxt, ptextLen, crtxt );
    return result == 0 ? M_RESULT_SUCCESS : M_ENCRYPTION_ERROR;
}

char AES_FPE_decrypt( const uint8_t* key, const TWEAK_PARAMS_DEF,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    char result = FPE_cipher( key, 0, TWEAK_AGRS, crtxt, crtxtLen, pntxt );
    return result == 0 ? M_RESULT_SUCCESS : M_DECRYPTION_ERROR;
}
