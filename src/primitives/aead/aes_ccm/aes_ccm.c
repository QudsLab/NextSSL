#include "aes_ccm.h"
#include "../../cipher/aes_core/aes_internal.h"
#include "../../cipher/aes_ctr/aes_ctr.h"

#define CCM_NONCE_LEN    11
#define CCM_TAG_LEN      16

static void CCMtag( const block_t iv, const void* aData, const void* pntxt,
                    const size_t aDataLen, const size_t ptextLen, block_t M )
{
    block_t A = { 0 };
    uint8_t p = 1, s = 0;

    memcpy( M, iv, BLOCKSIZE );
    M[0] |= (CCM_TAG_LEN - 2) << 2;
    xorBEint( M, ptextLen, LAST );

    if (aDataLen)
    {
        M[0] |= 0x40;
        rijndaelEncrypt( M, M );
        if (aDataLen > 0xFEFFL)
        {
            p += 4;
            A[0] = 0xFF,  A[1] = 0xFE;
        }
        xorBEint( A, aDataLen, p );
        s = sizeof A - ++p;
        memcpy( A + p, aData, aDataLen < s ? aDataLen : s );
    }

    xMac( A, sizeof A, M, &rijndaelEncrypt, M );
    if (aDataLen > s)
    {
        xMac( (char*) aData + s, aDataLen - s, M, &rijndaelEncrypt, M );
    }
    xMac( pntxt, ptextLen, M, &rijndaelEncrypt, M );

    rijndaelEncrypt( iv, A );
    xorBlock( A, M );
}

void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* tag = (uint8_t*) crtxt + ptextLen;
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, C;

    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    AES_setkey( key );
    CCMtag( iv, aData, pntxt, aDataLen, ptextLen, C );
    CTR_cipher( iv, CCM_GCM, pntxt, ptextLen, crtxt );
    AES_burn();

    memcpy( tag, C, CCM_TAG_LEN );
}

char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, C;

    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    AES_setkey( key );
    CTR_cipher( iv, CCM_GCM, crtxt, crtxtLen, pntxt );
    CCMtag( iv, aData, pntxt, aDataLen, crtxtLen, C );
    AES_burn();

    if (memcmp_s( tag, C, CCM_TAG_LEN ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
