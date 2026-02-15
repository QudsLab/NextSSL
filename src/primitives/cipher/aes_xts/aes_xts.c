#include "aes_xts.h"
#include "../../cipher/aes_core/aes_internal.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

static void XTS_cipher( const uint8_t* keypair, const char mode,
                        const block_t tweak, const size_t sectid,
                        const size_t dataSize, void* storage )
{
    fmix_t cipher = mode ? &rijndaelEncrypt : &rijndaelDecrypt;
    uint8_t r = dataSize % BLOCKSIZE, *y;
    count_t n = dataSize / BLOCKSIZE - (r > 0);
    block_t T;

    if (tweak == NULL)
    {
        memset( T, 0, sizeof T );
        copyLint( T, sectid, 0 );
    }
    else
    {
        memcpy( T, tweak, sizeof T );
    }
    AES_setkey( keypair + KEYSIZE );
    rijndaelEncrypt( T, T );

    AES_setkey( keypair );
    for (y = storage; n--; y += BLOCKSIZE)
    {
        xorBlock( T, y );
        cipher( y, y );
        xorBlock( T, y );
        doubleLblock( T );
    }
    if (r)
    {
        block_t L;
        memcpy( L, T, sizeof L );
        doubleLblock( mode ? T : L );

        xorBlock( L, y );
        cipher( y, y );
        xorBlock( L, y );
        memcpy( L, y, sizeof L );
        memcpy( y, y + BLOCKSIZE, r );
        memcpy( y + BLOCKSIZE, L, r );

        xorBlock( T, y );
        cipher( y, y );
        xorBlock( T, y );
    }
    AES_burn();
}

EXPORT char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* tweak,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    if (ptextLen < BLOCKSIZE)  return M_DATALENGTH_ERROR;

    memcpy( crtxt, pntxt, ptextLen );
    XTS_cipher( keys, 1, tweak, 0, ptextLen, crtxt );
    return M_RESULT_SUCCESS;
}

EXPORT char AES_XTS_decrypt( const uint8_t* keys, const uint8_t* tweak,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    if (crtxtLen < BLOCKSIZE)  return M_DATALENGTH_ERROR;

    memcpy( pntxt, crtxt, crtxtLen );
    XTS_cipher( keys, 0, tweak, 0, crtxtLen, pntxt );
    return M_RESULT_SUCCESS;
}
