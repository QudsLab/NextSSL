/**
 * @file nextssl.c
 * @brief Lite variant unified API implementation (Layer 4)
 * 
 * This is the ultra-simple wrapper for the lite variant.
 * Provides sensible defaults and minimal configuration.
 */

#include "nextssl.h"
#include "../../main/lite/hash.h"
#include "../../main/lite/aead.h"
#include "../../main/lite/password.h"
#include "../../main/lite/keyexchange.h"
#include "../../main/lite/signature.h"
#include "../../main/lite/pqc.h"
#include "../../main/lite/pow.h"
#include <string.h>

// ============================================================================
// Hash Functions (defaults to SHA-256)
// ============================================================================

int nextssl_hash(const uint8_t *data, size_t len, uint8_t *output) {
    return nextssl_lite_hash("SHA-256", data, len, output);
}

int nextssl_hash_with_algorithm(const char *algorithm, const uint8_t *data, size_t len, uint8_t *output) {
    return nextssl_lite_hash(algorithm, data, len, output);
}

// ============================================================================
// Encryption Functions (defaults to AES-256-GCM)
// ============================================================================

int nextssl_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext
) {
    return nextssl_lite_aead_encrypt("AES-256-GCM", key, nonce, NULL, 0, plaintext, plaintext_len, ciphertext);
}

int nextssl_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
) {
    return nextssl_lite_aead_decrypt("AES-256-GCM", key, nonce, NULL, 0, ciphertext, ciphertext_len, plaintext);
}

int nextssl_encrypt_with_aad(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext
) {
    return nextssl_lite_aead_encrypt("AES-256-GCM", key, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext);
}

int nextssl_decrypt_with_aad(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
) {
    return nextssl_lite_aead_decrypt("AES-256-GCM", key, nonce, aad, aad_len, ciphertext, ciphertext_len, plaintext);
}

// ============================================================================
// Password Hashing (Argon2id)
// ============================================================================

int nextssl_password_hash(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    uint8_t *output
) {
    // Call lite password hash with fixed salt size (16 bytes)
    return nextssl_lite_password_hash(password, plen, salt, 16, output);
}

int nextssl_password_verify(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    const uint8_t *expected_hash
) {
    // Call lite password verify with fixed salt size (16 bytes)
    return nextssl_lite_password_verify(password, plen, salt, 16, expected_hash);
}

// ============================================================================
// Key Derivation (HKDF)
// ============================================================================

int nextssl_kdf(
    const uint8_t *input_key,
    size_t input_key_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *output_key,
    size_t output_key_len
) {
    return nextssl_lite_kdf_derive(input_key, input_key_len, salt, salt_len, info, info_len, output_key, output_key_len);
}

// ============================================================================
// Key Exchange (defaults to X25519, can use Kyber1024)
// ============================================================================

int nextssl_keyexchange_keypair(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_lite_kyber1024_keygen(public_key, secret_key);
    } else {
        return nextssl_lite_x25519_keygen(public_key, secret_key);
    }
}

int nextssl_keyexchange_shared_secret(
    uint8_t *shared_secret,
    const uint8_t *my_secret_key,
    const uint8_t *their_public_key,
    int pqc
) {
    if (pqc) {
        // For PQC, "shared_secret" is actually the ciphertext output
        // This is a simplified wrapper - real usage needs proper handling
        return -1;  // Not directly applicable for KEM
    } else {
        return nextssl_lite_x25519_exchange(my_secret_key, their_public_key, shared_secret);
    }
}

// ============================================================================
// Digital Signatures (defaults to Ed25519, can use Dilithium5)
// ============================================================================

int nextssl_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_lite_dilithium5_keygen(public_key, secret_key);
    } else {
        return nextssl_lite_ed25519_keygen(public_key, secret_key);
    }
}

int nextssl_sign(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *secret_key,
    uint8_t *signature,
    int pqc
) {
    if (pqc) {
        size_t sig_len;
        return nextssl_lite_dilithium5_sign(message, mlen, secret_key, signature, &sig_len);
    } else {
        return nextssl_lite_ed25519_sign(message, mlen, secret_key, signature);
    }
}

int nextssl_verify(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *signature,
    const uint8_t *public_key,
    int pqc
) {
    if (pqc) {
        // Dilithium5 signature is fixed size 4627 bytes
        return nextssl_lite_dilithium5_verify(message, mlen, signature, NEXTSSL_LITE_DILITHIUM5_SIGNATURE_SIZE, public_key);
    } else {
        // Ed25519 signature is fixed size 64 bytes  
        return nextssl_lite_ed25519_verify(message, mlen, signature, public_key);
    }
}

// ============================================================================
// Proof-of-Work
// ============================================================================

int nextssl_pow_solve(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t *nonce,
    uint8_t *hash_output
) {
    if (challenge_len > 32) {
        return -1;
    }
    
    nextssl_lite_pow_challenge_t challenge;
    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.challenge, challenge_data, challenge_len);
    challenge.difficulty = difficulty;
    challenge.timestamp = 0;
    
    nextssl_lite_pow_solution_t solution;
    memset(&solution, 0, sizeof(solution));
    int result = nextssl_lite_pow_solve(&challenge, &solution, 300);  // 5 min timeout
    
    if (result == 0) {
        // Return first 8 bytes of nonce as uint64_t
        *nonce = 0;
        for (int i = 0; i < 8; i++) {
            *nonce |= (uint64_t)solution.nonce[i] << (i * 8);
        }
        memcpy(hash_output, solution.hash, 32);
    }
    
    return result;
}

int nextssl_pow_verify(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t nonce,
    const uint8_t *hash
) {
    if (challenge_len > 32) {
        return -1;
    }
    
    nextssl_lite_pow_challenge_t challenge;
    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.challenge, challenge_data, challenge_len);
    challenge.difficulty = difficulty;
    challenge.timestamp = 0;  // Not checked in lite variant
    
    nextssl_lite_pow_solution_t solution;
    memset(&solution, 0, sizeof(solution));
    // Convert nonce to bytes (little-endian)
    for (int i = 0; i < 8 && i < 32; i++) {
        solution.nonce[i] = (nonce >> (i * 8)) & 0xFF;
    }
    memcpy(solution.hash, hash, 32);
    solution.iterations = 0;  // Unknown
    
    return nextssl_lite_pow_verify(&challenge, &solution);
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* nextssl_version(void) {
    return "NextSSL v0.1.0-beta-lite";
}

int nextssl_algorithm_available(const char *algorithm) {
    return nextssl_lite_hash_available(algorithm) || 
           nextssl_lite_pqc_available();
}
