#include "aes_cbc.h"
#include "../../cipher/aes_core/aes_internal.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/* CTS (Ciphertext Stealing) is enabled by default in micro-AES if CBC is enabled. 
   We will support it here implicitly or explicitly. 
   The original code had #if CTS. I will include CTS logic. */

EXPORT char AES_CBC_encrypt( const uint8_t* key, const block_t iVec,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t const* iv = iVec;
    uint8_t r = ptextLen % BLOCKSIZE, *y;
    count_t n = ptextLen / BLOCKSIZE;

    /* CTS logic */
    if (n > 1 && !r && --n)  r = BLOCKSIZE;

    if (n == 0)  return M_DATALENGTH_ERROR;

    memcpy( crtxt, pntxt, ptextLen );

    AES_setkey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
        iv = y;
    }
    /* CTS handling or Padding */
    if (r)
    {
        block_t L = { 0 };
        memcpy( L, y, r );
        memcpy( y, y - BLOCKSIZE, r );
        y -= BLOCKSIZE;
        iv = L;
        
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
    }
    else if (padBlock( r, y )) /* If no CTS but padding needed (should not reach here if CTS logic above covers it) */
    {
         /* Note: Original code logic: if CTS, handles r. If not CTS, padBlock. 
            Here I assumed CTS is desired. If strict standard CBC is needed, we disable CTS.
            User asked for "CBC", usually implies PKCS#7 padding if not CTS.
            But micro-AES defaults CTS=1. I will stick to CTS as per original code. */
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
    }
    AES_burn();
    return M_RESULT_SUCCESS;
}

EXPORT char AES_CBC_decrypt( const uint8_t* key, const block_t iVec,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const *x = crtxt, *iv = iVec;
    uint8_t r = crtxtLen % BLOCKSIZE, *y;
    count_t n = crtxtLen / BLOCKSIZE;

    if (n > 1 && !r && --n)  r = BLOCKSIZE;

    if (n == 0)  return M_DATALENGTH_ERROR;
    
    n -= r > 0;

    AES_setkey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( x, y );
        xorBlock( iv, y );
        iv = x;
        x += BLOCKSIZE;
    }
    if (r)
    {
        const uint8_t* z = x + BLOCKSIZE;
        mixThenXor( &rijndaelDecrypt, x, y, z, r, y + BLOCKSIZE );
        memcpy( y, z, r );
        rijndaelDecrypt( y, y );
        xorBlock( iv, y );
    }
    AES_burn();
    return M_RESULT_SUCCESS;
}
