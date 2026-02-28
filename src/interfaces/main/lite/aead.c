/**
 * @file aead.c
 * @brief Lite variant AEAD implementation (AES-256-GCM, ChaCha20-Poly1305)
 */

#include "aead.h"
#include "../../../primitives/aead/aes_gcm/aes_gcm.h"
#include "../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"
#include <string.h>

#define NEXTSSL_LITE_AEAD_TAG_SIZE 16
#define NEXTSSL_LITE_AEAD_KEY_SIZE 32
#define NEXTSSL_LITE_AEAD_NONCE_SIZE 12

int nextssl_lite_aead_encrypt(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext
) {
    if (!key || !nonce || !plaintext || !ciphertext) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    // Default to AES-256-GCM
    if (!algorithm || strcmp(algorithm, "AES-256-GCM") == 0) {
        AES_GCM_encrypt(key, nonce, aad, aad_len,
                       plaintext, plaintext_len, ciphertext);
        return 0;
    }
    
    if (strcmp(algorithm, "ChaCha20-Poly1305") == 0) {
        ChaCha20_Poly1305_encrypt(key, nonce, aad, aad_len,
                                 plaintext, plaintext_len, ciphertext);
        return 0;
    }
    
    return -99;  // Algorithm not supported
}

int nextssl_lite_aead_decrypt(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
) {
    if (!key || !nonce || !ciphertext || !plaintext) {
        return -1;
    }
    
    if (ciphertext_len < NEXTSSL_LITE_AEAD_TAG_SIZE) {
        return -1;  // Too short to contain tag
    }
    
    size_t plaintext_len = ciphertext_len - NEXTSSL_LITE_AEAD_TAG_SIZE;
    const uint8_t *tag = ciphertext + plaintext_len;
    
    // Default to AES-256-GCM
    if (!algorithm || strcmp(algorithm, "AES-256-GCM") == 0) {
        /* AES_GCM_decrypt expects crtxtLen = plaintext length (tag at crtxt+crtxtLen) */
        if (AES_GCM_decrypt(key, nonce, aad, aad_len,
                           ciphertext, plaintext_len, plaintext) != 0) {
            return -5;  // NEXTSSL_ERROR_AUTH_FAIL (authentication failed)
        }
        
        return 0;
    }
    
    if (strcmp(algorithm, "ChaCha20-Poly1305") == 0) {
        if (ChaCha20_Poly1305_decrypt(key, nonce, aad, aad_len,
                                     ciphertext, plaintext_len + NEXTSSL_LITE_AEAD_TAG_SIZE,
                                     plaintext) != 0) {
            return -5;
        }
        
        return 0;
    }
    
    return -2;
}

int nextssl_lite_aead_overhead(const char *algorithm) {
    // Both algorithms use 16-byte authentication tag
    return NEXTSSL_LITE_AEAD_TAG_SIZE;
}

int nextssl_lite_aead_key_size(const char *algorithm) {
    return NEXTSSL_LITE_AEAD_KEY_SIZE;  // 32 bytes for both
}

int nextssl_lite_aead_nonce_size(const char *algorithm) {
    return NEXTSSL_LITE_AEAD_NONCE_SIZE;  // 12 bytes for both
}
