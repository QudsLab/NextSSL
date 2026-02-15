#include "aes_eax.h"
#include "../../cipher/aes_core/aes_internal.h"
#include "../../cipher/aes_ctr/aes_ctr.h"

#define EAX_NONCE_LEN    16
#define EAX_TAG_LEN      16

static void oMac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    dataSize ? memset( mac, 0, BLOCKSIZE ) : memcpy( mac, D, BLOCKSIZE );

    mac[LAST] ^= t;
    rijndaelEncrypt( mac, mac );

    if (dataSize == 0)  return;
    cMac( D, Q, data, dataSize, mac );
}

void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t D = { 0 }, Q, mac, tag;
    uint8_t* auth = (uint8_t*) crtxt + ptextLen;

    getSubkeys( &doubleBblock, 1, key, D, Q );
    oMac( 0, D, Q, nonce, EAX_NONCE_LEN, mac );
    CTR_cipher( mac, CTR_DEFAULT, pntxt, ptextLen, crtxt );

    oMac( 1, D, Q, aData, aDataLen, tag );
    xorBlock( mac, tag );
    oMac( 2, D, Q, crtxt, ptextLen, mac );
    xorBlock( mac, tag );
    memcpy( auth, tag, EAX_TAG_LEN );
    AES_burn();
}

char AES_EAX_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t D = { 0 }, Q, mac, tag;
    uint8_t const* auth = (uint8_t*) crtxt + crtxtLen;

    getSubkeys( &doubleBblock, 1, key, D, Q );
    oMac( 2, D, Q, crtxt, crtxtLen, tag );
    oMac( 1, D, Q, aData, aDataLen, mac );
    xorBlock( mac, tag );
    oMac( 0, D, Q, nonce, EAX_NONCE_LEN, mac );
    xorBlock( mac, tag );

    if (memcmp_s( auth, tag, EAX_TAG_LEN ))
    {
        AES_burn();
        return M_AUTHENTICATION_ERROR;
    }
    CTR_cipher( mac, CTR_DEFAULT, crtxt, crtxtLen, pntxt );
    AES_burn();
    return M_RESULT_SUCCESS;
}
