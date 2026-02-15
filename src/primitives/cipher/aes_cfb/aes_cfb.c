#include "aes_cfb.h"
#include "../../cipher/aes_core/aes_internal.h"

static void CFB_cipher( const uint8_t* key, const block_t iVec, const char mode,
                        const void* input, const size_t dataSize, void* output )
{
    uint8_t const *iv = iVec, *x = input;
    uint8_t* y;
    block_t tmp;
    count_t n = dataSize / BLOCKSIZE;

    AES_setkey( key );
    for (y = output; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, y );
        xorBlock( x, y );
        iv = mode ? y : x;
        x += BLOCKSIZE;
    }
    mixThenXor( &rijndaelEncrypt, iv, tmp, x, dataSize % BLOCKSIZE, y );
    AES_burn();
}

void AES_CFB_encrypt( const uint8_t* key, const block_t iVec,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    CFB_cipher( key, iVec, 1, pntxt, ptextLen, crtxt );
}

void AES_CFB_decrypt( const uint8_t* key, const block_t iVec,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    CFB_cipher( key, iVec, 0, crtxt, crtxtLen, pntxt );
}
