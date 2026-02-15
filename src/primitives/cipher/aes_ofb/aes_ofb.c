#include "aes_ofb.h"
#include "../../cipher/aes_core/aes_internal.h"

void AES_OFB_encrypt( const uint8_t* key, const block_t iVec,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    count_t n = ptextLen / BLOCKSIZE;
    uint8_t* y;
    block_t iv;

    memcpy( iv, iVec, sizeof iv );
    memcpy( crtxt, pntxt, ptextLen );

    AES_setkey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, iv );
        xorBlock( iv, y );
    }
    mixThenXor( &rijndaelEncrypt, iv, iv, y, ptextLen % BLOCKSIZE, y );
    AES_burn();
}

void AES_OFB_decrypt( const uint8_t* key, const block_t iVec,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    AES_OFB_encrypt( key, iVec, crtxt, crtxtLen, pntxt );
}
