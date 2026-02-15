#include "aes_fpe.h"
#include "../../cipher/aes_core/aes_internal.h"
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

/* FF3 implementation skipped for brevity unless requested, 
   but structure allows adding it if FF_X == 3 defined. 
   Assuming FF1 is the target as per standard usage. */

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
