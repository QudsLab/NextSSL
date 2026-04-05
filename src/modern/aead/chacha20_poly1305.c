#include "chacha20_poly1305.h"
#include "monocypher.h"
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define CHACHA20_TAG_LEN 16

// Error codes matching AES suite for consistency
#define M_AUTHENTICATION_ERROR 0x1A
#define M_RESULT_SUCCESS       0

EXPORT void ChaCha20_Poly1305_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt)
{
    crypto_aead_ctx ctx;
    uint8_t mac[CHACHA20_TAG_LEN];
    uint8_t* ciphertext_out = (uint8_t*)crtxt;
    uint8_t* tag_out = ciphertext_out + ptextLen;

    // Use IETF mode (12 byte nonce)
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext_out, mac, (const uint8_t*)aData, aDataLen, (const uint8_t*)pntxt, ptextLen);
    
    // Append tag to the end of ciphertext
    memcpy(tag_out, mac, CHACHA20_TAG_LEN);
    
    // Wipe context
    crypto_wipe(&ctx, sizeof(ctx));
}

EXPORT char ChaCha20_Poly1305_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt)
{
    crypto_aead_ctx ctx;
    uint8_t mac[CHACHA20_TAG_LEN];
    size_t text_len;
    int result;
    
    if (crtxtLen < CHACHA20_TAG_LEN) {
        return M_AUTHENTICATION_ERROR;
    }
    
    text_len = crtxtLen - CHACHA20_TAG_LEN;
    const uint8_t* ciphertext_in = (const uint8_t*)crtxt;
    const uint8_t* tag_in = ciphertext_in + text_len;
    
    // Extract tag
    memcpy(mac, tag_in, CHACHA20_TAG_LEN);
    
    crypto_aead_init_ietf(&ctx, key, nonce);
    result = crypto_aead_read(&ctx, (uint8_t*)pntxt, mac, (const uint8_t*)aData, aDataLen, ciphertext_in, text_len);
    
    crypto_wipe(&ctx, sizeof(ctx));
    
    if (result != 0) {
        // Verification failed
        memset(pntxt, 0, text_len); 
        return M_AUTHENTICATION_ERROR;
    }
    
    return M_RESULT_SUCCESS;
}
