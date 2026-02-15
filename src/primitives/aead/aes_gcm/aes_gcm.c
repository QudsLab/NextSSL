#include "aes_gcm.h"
#include "../../cipher/aes_core/aes_internal.h"
#include "../../cipher/aes_ctr/aes_ctr.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define GCM_NONCE_LEN    12
#define GCM_TAG_LEN      16

static void gHash( const block_t H, const void* aData, const void* crtxt,
                   const size_t aDataLen, const size_t crtxtLen, block_t gh )
{
    block_t len = { 0 };
    xorBEint( len, aDataLen * 8, MIDST );
    xorBEint( len, crtxtLen * 8, LAST );

    xMac( aData, aDataLen, H, &mulGF128, gh );
    xMac( crtxt, crtxtLen, H, &mulGF128, gh );
    xMac( len, sizeof len, H, &mulGF128, gh );
}

static void GCMsetup( const uint8_t* key,
                      const uint8_t* nonce, block_t auKey, block_t iv )
{
    AES_setkey( key );
    rijndaelEncrypt( auKey, auKey );
    if (GCM_NONCE_LEN != 12)
    {
        gHash( auKey, NULL, nonce, 0, GCM_NONCE_LEN, iv );
        return;
    }
    memcpy( iv, nonce, 12 );
    iv[LAST] = 1;
}

EXPORT void AES_GCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* tag = (uint8_t*) crtxt + ptextLen;
    block_t iv = { 0 }, H = { 0 }, G = { 0 };
    block_t tagMask;

    GCMsetup( key, nonce, H, iv );

    // Calculate tag mask from Y0
    rijndaelEncrypt( iv, tagMask );

    // Increment IV to Y1 for data encryption
    iv[LAST]++;

    CTR_cipher( iv, CCM_GCM, pntxt, ptextLen, crtxt );
    AES_burn();

    gHash( H, aData, crtxt, aDataLen, ptextLen, G );
    xorBlock( tagMask, G );
    memcpy( tag, G, GCM_TAG_LEN );
}

EXPORT char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;
    block_t H = { 0 }, iv = { 0 }, G = { 0 };

    GCMsetup( key, nonce, H, iv );
    gHash( H, aData, crtxt, aDataLen, crtxtLen, G );
    rijndaelEncrypt( iv, H );
    xorBlock( H, G );

    if (memcmp_s( tag, G, GCM_TAG_LEN ))
    {
        AES_burn();
        return M_AUTHENTICATION_ERROR;
    }

    // Increment IV to Y1 for data decryption
    iv[LAST]++;

    CTR_cipher( iv, CCM_GCM, crtxt, crtxtLen, pntxt );
    AES_burn();
    return M_RESULT_SUCCESS;
}
