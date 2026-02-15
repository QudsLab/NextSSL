#include "aes_siv.h"
#include "../../cipher/aes_core/aes_internal.h"
#include "../../cipher/aes_ctr/aes_ctr.h"

static void S2V( const uint8_t* key, const void* aData, const void* pntxt,
                 const size_t aDataLen, const size_t ptextLen, block_t IV )
{
    block_t K[2] = { { 0 } }, Y;
    uint8_t r, *Q = K[1];

    memcpy( IV, *K, BLOCKSIZE );
    getSubkeys( &doubleBblock, 1, key, *K, Q );
    rijndaelEncrypt( *K, Y );

    if (aDataLen)
    {
        cMac( *K, Q, aData, aDataLen, IV );
        doubleBblock( Y );
        xorBlock( IV, Y );
        memset( IV, 0, BLOCKSIZE );
    }
    if (ptextLen < sizeof Y)
    {
        doubleBblock( Y );
        r = 0;
    }
    else if ((r = ptextLen % sizeof Y) > 0)
    {
        memset( *K, 0, BLOCKSIZE );
    }
    xorBlock( Y, *K + r );
    cMac( *K, *K, pntxt, ptextLen - r, IV );

    if (r == 0)  return;

    cMac( NULL, Q, (char*) pntxt + ptextLen - r, r, IV );
}

void AES_SIV_encrypt( const uint8_t* keys,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen,
                      block_t iv, void* crtxt )
{
    S2V( keys, aData, pntxt, aDataLen, ptextLen, iv );
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, SIV_CTR, pntxt, ptextLen, crtxt );
    AES_burn();
}

char AES_SIV_decrypt( const uint8_t* keys, const block_t iv,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t IV;
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, SIV_CTR, crtxt, crtxtLen, pntxt );
    S2V( keys, aData, pntxt, aDataLen, crtxtLen, IV );
    AES_burn();

    if (memcmp_s( IV, iv, sizeof IV ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
