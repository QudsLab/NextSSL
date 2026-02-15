#include "aes_ecb.h"
#include "../../../primitives/cipher/aes_core/aes_internal.h"

void AES_ECB_encrypt( const uint8_t* key,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* y;
    count_t n = ptextLen / BLOCKSIZE;
    memcpy( crtxt, pntxt, ptextLen );

    AES_setkey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( y, y );
    }
    if (padBlock( ptextLen % BLOCKSIZE, y ))
    {
        rijndaelEncrypt( y, y );
    }
    AES_burn();
}

char AES_ECB_decrypt( const uint8_t* key,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t* y;
    count_t n = crtxtLen / BLOCKSIZE;
    memcpy( pntxt, crtxt, crtxtLen );

    AES_setkey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( y, y );
    }
    AES_burn();

    return crtxtLen % BLOCKSIZE ? M_DECRYPTION_ERROR : M_RESULT_SUCCESS;
}
