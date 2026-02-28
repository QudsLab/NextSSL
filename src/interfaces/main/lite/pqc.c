/**
 * @file pqc.c
 * @brief Lite variant unified PQC implementation (Kyber1024 + Dilithium5)
 */

#include "pqc.h"
#include "keyexchange.h"
#include "signature.h"
#include <string.h>

int nextssl_lite_pqc_keygen_combined(
    uint8_t *kem_public,
    uint8_t *kem_secret,
    uint8_t *sign_public,
    uint8_t *sign_secret
) {
    if (!kem_public || !kem_secret || !sign_public || !sign_secret) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    int result;
    
    // Generate Kyber1024 KEM keypair
    result = nextssl_lite_kyber1024_keygen(kem_public, kem_secret);
    if (result != 0) {
        return result;
    }
    
    // Generate Dilithium5 signature keypair
    result = nextssl_lite_dilithium5_keygen(sign_public, sign_secret);
    if (result != 0) {
        return result;
    }
    
    return 0;
}

int nextssl_lite_pqc_info(char *buffer, size_t size) {
    if (!buffer || size < 100) return -1;
    
    const char *info = "PQC Lite: Kyber1024 (KEM) + Dilithium5 (Sign)";
    size_t len = strlen(info);
    if (len >= size) len = size - 1;
    
    memcpy(buffer, info, len);
    buffer[len] = '\0';
    
    return 0;
}

int nextssl_lite_pqc_available(void) {
    return 1;  // Always available in lite build
}

// Convenience wrapper for full PQC workflow
int nextssl_lite_pqc_encrypt_and_sign(
    uint8_t *kem_ciphertext,
    uint8_t *kem_shared_secret,
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *recipient_kem_public,
    const uint8_t *sender_sign_secret
) {
    if (!kem_ciphertext || !kem_shared_secret || !signature || !signature_len ||
        !message || !recipient_kem_public || !sender_sign_secret) {
        return -1;
    }
    
    int result;
    
    // Encapsulate to get shared secret (parameter order: their_public, ciphertext, shared_secret)
    result = nextssl_lite_kyber1024_encaps(recipient_kem_public, kem_ciphertext, kem_shared_secret);
    if (result != 0) return result;
    
    // Sign the message (parameter order: message, message_len, secret_key, signature, signature_len)
    result = nextssl_lite_dilithium5_sign(message, message_len, sender_sign_secret, signature, signature_len);
    if (result != 0) return result;
    
    return 0;
}

int nextssl_lite_pqc_decrypt_and_verify(
    uint8_t *kem_shared_secret,
    const uint8_t *kem_ciphertext,
    const uint8_t *recipient_kem_secret,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sender_sign_public
) {
    if (!kem_shared_secret || !kem_ciphertext || !recipient_kem_secret ||
        !signature || !message || !sender_sign_public) {
        return -1;
    }
    
    int result;
    
    // Decapsulate to get shared secret (parameter order: ciphertext, secret_key, shared_secret)
    result = nextssl_lite_kyber1024_decaps(kem_ciphertext, recipient_kem_secret, kem_shared_secret);
    if (result != 0) return result;
    
    // Verify the signature (parameter order: message, message_len, signature, signature_len, public_key)
    result = nextssl_lite_dilithium5_verify(message, message_len, signature, signature_len, sender_sign_public);
    if (result != 0) return result;
    
    return 0;
}
