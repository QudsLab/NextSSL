#include "aes_kw.h"
#include "../../cipher/aes_core/aes_internal.h"

char AES_KEY_wrap( const uint8_t* kek,
                   const void* secret, const size_t secretLen, void* wrapped )
{
    uint8_t *w = wrapped;
    uint8_t *r = w + HB, *endpoint = w + secretLen;
    block_t A;
    count_t i, n = secretLen / HB;

    if (n < 2 || secretLen % HB)  return M_DATALENGTH_ERROR;

    memset( A, 0xA6, HB );
    memcpy( r, secret, secretLen );
    AES_setkey( kek );

    for (i = 0, n *= 6; i++ < n; )
    {
        memcpy( A + HB, r, HB );
        rijndaelEncrypt( A, A );
        memcpy( r, A + HB, HB );
        xorBEint( A, i, MIDST );
        r = (r == endpoint ? w : r) + HB;
    }
    AES_burn();

    memcpy( w, A, HB );
    return M_RESULT_SUCCESS;
}

char AES_KEY_unwrap( const uint8_t* kek,
                     const void* wrapped, const size_t wrapLen, void* secret )
{
    uint8_t const* w = wrapped;
    uint8_t *r = secret, *end = (uint8_t*) secret + wrapLen - HB;
    block_t A;
    count_t i, n = wrapLen / HB;

    if (n < 0x3 || wrapLen % HB)  return M_DATALENGTH_ERROR;

    memcpy( A, w, HB );
    memcpy( r, w + HB, wrapLen - HB );
    AES_setkey( kek );

    for (--n, i = n * 6; i; --i)
    {
        r = (r == secret ? end : r) - HB;
        xorBEint( A, i, MIDST );
        memcpy( A + HB, r, HB );
        rijndaelDecrypt( A, A );
        memcpy( r, A + HB, HB );
    }
    AES_burn();

    for (n = 0, i = HB; i--; )
    {
        n |= A[i] - 0xA6;
    }
    return n ? M_AUTHENTICATION_ERROR : M_RESULT_SUCCESS;
}
