#include "aes_gcm_siv.h"
#include "../../cipher/aes_core/aes_internal.h"
#include "../../cipher/aes_ctr/aes_ctr.h"

#define SIVGCM_NONCE_LEN 12
#define SIVGCM_TAG_LEN   16

static void polyval( const block_t H, const void* aData, const void* pntxt,
                     const size_t aDataLen, const size_t ptextLen, block_t pv )
{
    block_t len = { 0 };
    copyLint( len, aDataLen * 8, 0 );
    copyLint( len, ptextLen * 8, HB );

    xMac( aData, aDataLen, H, &dotGF128, pv );
    xMac( pntxt, ptextLen, H, &dotGF128, pv );
    xMac( len, sizeof len, H, &dotGF128, pv );
}

static void GCM_SIVsetup( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t iv[5 * HB + KEYSIZE], *h, *k;
    k = h = iv + BLOCKSIZE;
    memcpy( iv + 4, nonce, SIVGCM_NONCE_LEN );

    AES_setkey( key );
    for (*(int32_t*) iv = 0; *iv < 2 + Nk / 2; ++*iv)
    {
        rijndaelEncrypt( iv, k );
        k += HB;
    }
    AES_setkey( k - KEYSIZE );
    memcpy( AK, h, BLOCKSIZE );
}

static void GCM_SIVtag( const uint8_t* nonce, block_t pv, block_t tag )
{
    XOR32BITS( nonce[0], pv[0] );
    XOR32BITS( nonce[4], pv[4] );
    XOR32BITS( nonce[8], pv[8] );
    pv[LAST] &= 0x7F;
    rijndaelEncrypt( pv, tag );
}

void GCM_SIV_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t P = { 0 };
    uint8_t *H, *tag = (uint8_t*) crtxt + ptextLen;

    H = tag;
    GCM_SIVsetup( key, nonce, H );
    polyval( H, aData, pntxt, aDataLen, ptextLen, P );
    GCM_SIVtag( nonce, P, tag );
    CTR_cipher( tag, SIVGCM_CTR, pntxt, ptextLen, crtxt );
    AES_burn();
}

char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t H, P = { 0 };
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;

    GCM_SIVsetup( key, nonce, H );
    CTR_cipher( tag, SIVGCM_CTR, crtxt, crtxtLen, pntxt );
    polyval( H, aData, pntxt, aDataLen, crtxtLen, P );
    GCM_SIVtag( nonce, P, P );
    AES_burn();

    if (memcmp_s( tag, P, SIVGCM_TAG_LEN ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
