/**
 * @file profiles_common.c
 * @brief Common profile definitions (available in both lite and full)
 * 
 * MODERN: Default safe profile
 * - Hash: SHA-256
 * - AEAD: AES-256-GCM
 * - KDF: Argon2id
 * - Sign: Ed25519
 * - KEM: ML-KEM-1024 (post-quantum)
 * 
 * COMPLIANCE: FIPS/NIST compliant
 * - Hash: SHA-256
 * - AEAD: AES-256-GCM
 * - KDF: HKDF-SHA256
 * - Sign: Ed25519
 * - KEM: ML-KEM-1024
 * 
 * PQC: Post-quantum only
 * - Hash: BLAKE3 (quantum-safe)
 * - AEAD: AES-256-GCM (quantum-safe for confidentiality)
 * - KDF: Argon2id
 * - Sign: ML-DSA-87 (post-quantum)
 * - KEM: ML-KEM-1024 (post-quantum)
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#include "profiles.h"
#include <string.h>

int nextssl_profile_load(nextssl_profile_t profile, nextssl_config_t *config) {
    if (config == NULL) {
        return -1;
    }
    
    /* Clear config */
    memset(config, 0, sizeof(nextssl_config_t));
    
    config->profile = profile;
    config->profile_name = nextssl_config_profile_name(profile);
    
    switch (profile) {
        case NEXTSSL_PROFILE_MODERN:
            /* Default: Modern safe algorithms */
            config->default_hash = NEXTSSL_HASH_SHA256;
            config->default_aead = NEXTSSL_AEAD_AES_256_GCM;
            config->default_kdf = NEXTSSL_KDF_ARGON2ID;
            config->default_sign = NEXTSSL_SIGN_ED25519;
            config->default_kem = NEXTSSL_KEM_ML_KEM_1024;
            config->strict_mode = true;
            config->allow_legacy = false;
            config->pqc_only = false;
            break;
            
        case NEXTSSL_PROFILE_COMPLIANCE:
            /* FIPS/NIST compliance */
            config->default_hash = NEXTSSL_HASH_SHA256;
            config->default_aead = NEXTSSL_AEAD_AES_256_GCM;
            config->default_kdf = NEXTSSL_KDF_HKDF_SHA256;
            config->default_sign = NEXTSSL_SIGN_ED25519;
            config->default_kem = NEXTSSL_KEM_ML_KEM_1024;
            config->strict_mode = true;
            config->allow_legacy = false;
            config->pqc_only = false;
            break;
            
        case NEXTSSL_PROFILE_PQC:
            /* Post-quantum cryptography */
            config->default_hash = NEXTSSL_HASH_BLAKE3;
            config->default_aead = NEXTSSL_AEAD_AES_256_GCM;
            config->default_kdf = NEXTSSL_KDF_ARGON2ID;
            config->default_sign = NEXTSSL_SIGN_ML_DSA_87;
            config->default_kem = NEXTSSL_KEM_ML_KEM_1024;
            config->strict_mode = true;
            config->allow_legacy = false;
            config->pqc_only = true;  /* Require post-quantum */
            break;
            
#ifndef NEXTSSL_BUILD_LITE
        case NEXTSSL_PROFILE_COMPATIBILITY:
            /* Broad compatibility (includes legacy) */
            config->default_hash = NEXTSSL_HASH_SHA256;
            config->default_aead = NEXTSSL_AEAD_AES_256_GCM;
            config->default_kdf = NEXTSSL_KDF_PBKDF2;
            config->default_sign = NEXTSSL_SIGN_RSA_3072_PSS;
            config->default_kem = NEXTSSL_KEM_ECDH_P256;
            config->strict_mode = false;
            config->allow_legacy = true;
            config->pqc_only = false;
            break;
            
        case NEXTSSL_PROFILE_EMBEDDED:
            /* Resource-constrained devices */
            config->default_hash = NEXTSSL_HASH_BLAKE2S;
            config->default_aead = NEXTSSL_AEAD_CHACHA20_POLY1305;
            config->default_kdf = NEXTSSL_KDF_ARGON2ID;
            config->default_sign = NEXTSSL_SIGN_ED25519;
            config->default_kem = NEXTSSL_KEM_X25519;
            config->strict_mode = true;
            config->allow_legacy = false;
            config->pqc_only = false;
            break;
            
        case NEXTSSL_PROFILE_RESEARCH:
            /* All algorithms available (experimental) */
            config->default_hash = NEXTSSL_HASH_BLAKE3;
            config->default_aead = NEXTSSL_AEAD_AEGIS_256;
            config->default_kdf = NEXTSSL_KDF_ARGON2ID;
            config->default_sign = NEXTSSL_SIGN_ML_DSA_87;
            config->default_kem = NEXTSSL_KEM_ML_KEM_1024;
            config->strict_mode = false;
            config->allow_legacy = true;
            config->pqc_only = false;
            break;
#endif
            
        default:
            return -1;  /* Invalid profile */
    }
    
    return 0;
}
