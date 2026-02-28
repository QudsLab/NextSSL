/**
 * @file signature.c
 * @brief Lite variant signature implementation (Ed25519, Dilithium5)
 */

#include "signature.h"
#include "../../../primitives/ecc/ed25519/ed25519.h"
#include "../../../PQCrypto/crypto_sign/ml-dsa-87/clean/api.h"
#include <string.h>

// Ed25519 functions
int nextssl_lite_ed25519_keygen(uint8_t *public_key, uint8_t *secret_key) {
    if (!public_key || !secret_key) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    // Generate seed (in real use, should use CSPRNG)
    unsigned char seed[32];
    memcpy(seed, secret_key, 32);  // Assume secret_key contains seed
    
    // Generate Ed25519 keypair
    ed25519_create_keypair(public_key, secret_key, seed);
    
    return 0;
}

int nextssl_lite_ed25519_sign(
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[NEXTSSL_LITE_ED25519_SECRET_KEY_SIZE],
    uint8_t signature[NEXTSSL_LITE_ED25519_SIGNATURE_SIZE]
) {
    if (!signature || !message || !secret_key) {
        return -1;
    }
    
    // Ed25519 secret key is 64 bytes: first 32 = private, last 32 = public
    const uint8_t *public_key = secret_key + 32;
    
    // Ed25519 signing
    ed25519_sign(signature, message, message_len, public_key, secret_key);
    
    return 0;
}

int nextssl_lite_ed25519_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t signature[NEXTSSL_LITE_ED25519_SIGNATURE_SIZE],
    const uint8_t public_key[NEXTSSL_LITE_ED25519_PUBLIC_KEY_SIZE]
) {
    if (!signature || !message || !public_key) {
        return -1;
    }
    
    // Ed25519 verification (returns 1 if valid, 0 if invalid)
    int valid = ed25519_verify(signature, message, message_len, public_key);
    
    return valid ? 0 : -5;  // NEXTSSL_ERROR_AUTH_FAIL if invalid
}

// Dilithium5 functions
int nextssl_lite_dilithium5_keygen(uint8_t *public_key, uint8_t *secret_key) {
    if (!public_key || !secret_key) {
        return -1;
    }
    
    // Generate ML-DSA-87 keypair
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(public_key, secret_key) != 0) {
        return -4;  // NEXTSSL_ERROR_CRYPTO_FAIL
    }
    
    return 0;
}

int nextssl_lite_dilithium5_sign(
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[NEXTSSL_LITE_DILITHIUM5_SECRET_KEY_SIZE],
    uint8_t signature[NEXTSSL_LITE_DILITHIUM5_SIGNATURE_SIZE],
    size_t *signature_len
) {
    if (!signature || !signature_len || !message || !secret_key) {
        return -1;
    }
    
    // ML-DSA-87 signing
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) != 0) {
        return -4;
    }
    
    return 0;
}

int nextssl_lite_dilithium5_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t public_key[NEXTSSL_LITE_DILITHIUM5_PUBLIC_KEY_SIZE]
) {
    if (!signature || !message || !public_key) {
        return -1;
    }
    
    // ML-DSA-87 verification (returns 0 if valid, non-zero if invalid)
    int result = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(signature, signature_len, message, message_len, public_key);
    
    return (result == 0) ? 0 : -5;  // NEXTSSL_ERROR_AUTH_FAIL if invalid
}

// Hybrid signing (Ed25519 + Dilithium5)
int nextssl_lite_hybrid_sign_keypair(
    uint8_t *ed25519_public,
    uint8_t *ed25519_secret,
    uint8_t *dilithium_public,
    uint8_t *dilithium_secret
) {
    int result;
    
    result = nextssl_lite_ed25519_keygen(ed25519_public, ed25519_secret);
    if (result != 0) return result;
    
    result = nextssl_lite_dilithium5_keygen(dilithium_public, dilithium_secret);
    if (result != 0) return result;
    
    return 0;
}

int nextssl_lite_hybrid_sign(
    uint8_t *ed25519_sig,
    uint8_t *dilithium_sig,
    size_t *dilithium_sig_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *ed25519_secret,
    const uint8_t *dilithium_secret
) {
    int result;
    
    // Ed25519 signature
    result = nextssl_lite_ed25519_sign(message, message_len, ed25519_secret, ed25519_sig);
    if (result != 0) return result;
    
    // Dilithium5 signature
    result = nextssl_lite_dilithium5_sign(message, message_len, dilithium_secret, dilithium_sig, dilithium_sig_len);
    if (result != 0) return result;
    
    return 0;
}

int nextssl_lite_hybrid_verify(
    const uint8_t *ed25519_sig,
    const uint8_t *dilithium_sig,
    size_t dilithium_sig_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *ed25519_public,
    const uint8_t *dilithium_public
) {
    int result;
    
    // Verify Ed25519 signature
    result = nextssl_lite_ed25519_verify(message, message_len, ed25519_sig, ed25519_public);
    if (result != 0) return result;
    
    // Verify Dilithium5 signature
    result = nextssl_lite_dilithium5_verify(message, message_len, dilithium_sig, dilithium_sig_len, dilithium_public);
    if (result != 0) return result;
    
    return 0;  // Both signatures valid
}
