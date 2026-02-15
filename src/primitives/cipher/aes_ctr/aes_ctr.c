#include "aes_ctr.h"
#include "../../cipher/aes_core/aes_internal.h"

#define CTR_START_VALUE  1
#define CTR_IV_LENGTH    12

void CTR_cipher( const block_t iCtr, const char mode,
                        const void* input, const size_t dataSize, void* output )
{
    block_t c, enc;
    count_t n = dataSize / BLOCKSIZE;
    uint8_t index = LAST, *y;

    if (input != output) memcpy( output, input, dataSize );
    memcpy( c, iCtr, sizeof c );

    switch (mode)
    {
    case SIV_CTR:
        c[+8] &= 0x7F;
        c[12] &= 0x7F;
        break;
    case SIVGCM_CTR:
        c[LAST] |= 0x80;
        index = 0;
        break;
    case CCM_GCM:
        incBlock( c, index );
        break;
    }
    for (y = output; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( c, enc );
        xorBlock( enc, y );
        incBlock( c, index );
    }
    mixThenXor( &rijndaelEncrypt, c, c, y, dataSize % BLOCKSIZE, y );
}

void AES_CTR_encrypt( const uint8_t* key, const uint8_t* iv,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t ctr = { 0 };
    memcpy( ctr, iv, CTR_IV_LENGTH );
    xorBEint( ctr, CTR_START_VALUE, LAST );

    AES_setkey( key );
    CTR_cipher( ctr, CTR_DEFAULT, pntxt, ptextLen, crtxt );
    AES_burn();
}

void AES_CTR_decrypt( const uint8_t* key, const uint8_t* iv,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    AES_CTR_encrypt( key, iv, crtxt, crtxtLen, pntxt );
}
