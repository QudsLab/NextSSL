/**
 * @file keyexchange.c
 * @brief Lite variant key exchange implementation (X25519, Kyber1024)
 */

#include "keyexchange.h"
#include "../../../primitives/ecc/ed25519/ed25519.h"
#include "../../../PQCrypto/crypto_kem/ml-kem-1024/clean/api.h"
#include <string.h>

// X25519 functions
int nextssl_lite_x25519_keygen(uint8_t *public_key, uint8_t *secret_key) {
    if (!public_key || !secret_key) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }

    /* ed25519_create_keypair writes 64 bytes to secret_key (seed||pubkey).
     * Use an internal 64-byte buffer, then copy only the 32-byte private
     * scalar into the caller's buffer.                                   */
    unsigned char seed[32];
    unsigned char sk_full[64];

    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, sk_full, seed);

    /* sk_full[0..31] is the clamped Curve25519 scalar used by key_exchange */
    memcpy(secret_key, sk_full, 32);

    return 0;
}

int nextssl_lite_x25519_exchange(
    const uint8_t *my_secret_key,
    const uint8_t *their_public_key,
    uint8_t *shared_secret
) {
    if (!shared_secret || !my_secret_key || !their_public_key) {
        return -1;
    }
    
    ed25519_key_exchange(shared_secret, their_public_key, my_secret_key);
    
    return 0;
}

// Kyber1024 functions
int nextssl_lite_kyber1024_keygen(uint8_t *public_key, uint8_t *secret_key) {
    if (!public_key || !secret_key) {
        return -1;
    }
    
    // Call ML-KEM-1024 key generation
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(public_key, secret_key) != 0) {
        return -4;  // NEXTSSL_ERROR_CRYPTO_FAIL
    }
    
    return 0;
}

int nextssl_lite_kyber1024_encaps(
    const uint8_t *their_public,
    uint8_t *ciphertext,
    uint8_t *shared_secret
) {
    if (!ciphertext || !shared_secret || !their_public) {
        return -1;
    }
    
    // Call ML-KEM-1024 encapsulation
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ciphertext, shared_secret, their_public) != 0) {
        return -4;
    }
    
    return 0;
}

int nextssl_lite_kyber1024_decaps(
    const uint8_t *ciphertext,
    const uint8_t *my_secret,
    uint8_t *shared_secret
) {
    if (!shared_secret || !ciphertext || !my_secret) {
        return -1;
    }
    
    // Call ML-KEM-1024 decapsulation
    if (PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext, my_secret) != 0) {
        return -4;
    }
    
    return 0;
}

// Hybrid key exchange (X25519 + Kyber1024)
int nextssl_lite_hybrid_keypair(
    uint8_t *x25519_public,
    uint8_t *x25519_secret,
    uint8_t *kyber_public,
    uint8_t *kyber_secret
) {
    int result;
    
    result = nextssl_lite_x25519_keygen(x25519_public, x25519_secret);
    if (result != 0) return result;
    
    result = nextssl_lite_kyber1024_keygen(kyber_public, kyber_secret);
    if (result != 0) return result;
    
    return 0;
}

int nextssl_lite_hybrid_encapsulate(
    uint8_t *x25519_shared,
    uint8_t *kyber_ciphertext,
    uint8_t *kyber_shared,
    const uint8_t *x25519_their_public,
    const uint8_t *x25519_my_secret,
    const uint8_t *kyber_their_public
) {
    int result;
    
    // X25519 ECDH
    result = nextssl_lite_x25519_exchange(x25519_my_secret, x25519_their_public, x25519_shared);
    if (result != 0) return result;
    
    // Kyber1024 encapsulation
    result = nextssl_lite_kyber1024_encaps(kyber_their_public, kyber_ciphertext, kyber_shared);
    if (result != 0) return result;
    
    return 0;
}

int nextssl_lite_hybrid_decapsulate(
    uint8_t *x25519_shared,
   uint8_t *kyber_shared,
    const uint8_t *x25519_their_public,
    const uint8_t *x25519_my_secret,
    const uint8_t *kyber_ciphertext,
    const uint8_t *kyber_my_secret
) {
    int result;
    
    // X25519 ECDH
    result = nextssl_lite_x25519_exchange(x25519_my_secret, x25519_their_public, x25519_shared);
    if (result != 0) return result;
    
    // Kyber1024 decapsulation
    result = nextssl_lite_kyber1024_decaps(kyber_ciphertext, kyber_my_secret, kyber_shared);
    if (result != 0) return result;
    
    return 0;
}
