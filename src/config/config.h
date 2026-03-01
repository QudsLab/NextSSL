/**
 * @file config.h
 * @brief NextSSL Configuration System
 * 
 * Immutable profile-based configuration with compile-time validation.
 * Config is set once at initialization and cannot be changed at runtime.
 * 
 * Philosophy (from design doc):
 * - Defaults should be opinionated and hard
 * - Profiles over algorithm shopping
 * - Intent-based API (users choose use-case, not primitives)
 * - Strict validation (only compiled algorithms accepted)
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#ifndef NEXTSSL_PROFILES_CONFIG_H
#define NEXTSSL_PROFILES_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * PROFILE TYPES
 * ======================================================================== */

/**
 * @brief Security profiles (immutable after init)
 * 
 * Profiles map user intent to safe algorithm combinations.
 * Users choose profiles, not individual algorithms.
 */
typedef enum {
    NEXTSSL_PROFILE_MODERN = 0,      /**< Default: SHA-256, AES-256-GCM, Ed25519, X25519 */
    NEXTSSL_PROFILE_COMPLIANCE,      /**< FIPS/NIST: SHA-256/384, AES-256-GCM, ECDSA-P256 */
    NEXTSSL_PROFILE_PQC,             /**< Post-quantum: BLAKE3, AES-256-GCM, ML-DSA-87, ML-KEM-1024 */
    
    /* Full variant only */
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_PROFILE_COMPATIBILITY,   /**< Broad support: includes SHA-1, legacy modes */
    NEXTSSL_PROFILE_EMBEDDED,        /**< Resource-constrained: ChaCha20-Poly1305, small keys */
    NEXTSSL_PROFILE_RESEARCH,        /**< Experimental: all algorithms including unsafe */
#endif
    
    NEXTSSL_PROFILE_MAX
} nextssl_profile_t;

/**
 * @brief Algorithm identifiers (validated against compile-time availability)
 */
typedef enum {
    /* Hash Functions */
    NEXTSSL_HASH_SHA256 = 0,
    NEXTSSL_HASH_SHA512,
    NEXTSSL_HASH_BLAKE3,
    
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_HASH_SHA384,
    NEXTSSL_HASH_SHA1,
    NEXTSSL_HASH_MD5,           /* Legacy only */
    NEXTSSL_HASH_BLAKE2B,
    NEXTSSL_HASH_BLAKE2S,
    NEXTSSL_HASH_SHA3_256,
    NEXTSSL_HASH_SHA3_512,
#endif
    
    NEXTSSL_HASH_MAX
} nextssl_hash_algo_t;

typedef enum {
    /* AEAD Ciphers */
    NEXTSSL_AEAD_AES_256_GCM = 0,
    NEXTSSL_AEAD_CHACHA20_POLY1305,
    
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_AEAD_AES_128_GCM,
    NEXTSSL_AEAD_AES_256_CCM,
    NEXTSSL_AEAD_AES_128_CCM,
    NEXTSSL_AEAD_AEGIS_256,
    NEXTSSL_AEAD_XCHACHA20_POLY1305,
#endif
    
    NEXTSSL_AEAD_MAX
} nextssl_aead_algo_t;

typedef enum {
    /* Key Derivation */
    NEXTSSL_KDF_HKDF_SHA256 = 0,
    NEXTSSL_KDF_ARGON2ID,
    
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_KDF_HKDF_SHA512,
    NEXTSSL_KDF_ARGON2I,
    NEXTSSL_KDF_ARGON2D,
    NEXTSSL_KDF_SCRYPT,
    NEXTSSL_KDF_PBKDF2,
#endif
    
    NEXTSSL_KDF_MAX
} nextssl_kdf_algo_t;

typedef enum {
    /* Signature Algorithms */
    NEXTSSL_SIGN_ED25519 = 0,
    NEXTSSL_SIGN_ML_DSA_87,         /* Dilithium5 standardized */
    
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_SIGN_ED448,
    NEXTSSL_SIGN_ML_DSA_65,         /* Dilithium3 */
    NEXTSSL_SIGN_ML_DSA_44,         /* Dilithium2 */
    NEXTSSL_SIGN_FALCON_1024,
    NEXTSSL_SIGN_FALCON_512,
    NEXTSSL_SIGN_SPHINCS_256F,
    NEXTSSL_SIGN_ECDSA_P256,
    NEXTSSL_SIGN_ECDSA_P384,
    NEXTSSL_SIGN_RSA_3072_PSS,      /* Legacy compatibility */
#endif
    
    NEXTSSL_SIGN_MAX
} nextssl_sign_algo_t;

typedef enum {
    /* Key Exchange / KEM */
    NEXTSSL_KEM_X25519 = 0,
    NEXTSSL_KEM_ML_KEM_1024,        /* Kyber1024 standardized */
    
#ifndef NEXTSSL_BUILD_LITE
    NEXTSSL_KEM_X448,
    NEXTSSL_KEM_ML_KEM_768,         /* Kyber768 */
    NEXTSSL_KEM_ML_KEM_512,         /* Kyber512 */
    NEXTSSL_KEM_HQC_256,
    NEXTSSL_KEM_BIKE_L5,
    NEXTSSL_KEM_ECDH_P256,
    NEXTSSL_KEM_ECDH_P384,
#endif
    
    NEXTSSL_KEM_MAX
} nextssl_kem_algo_t;

/* ========================================================================
 * CONFIGURATION STRUCTURE
 * ======================================================================== */

/**
 * @brief Immutable configuration context
 * 
 * Once initialized, config cannot be changed.
 * Thread-safe to read after initialization.
 */
typedef struct {
    nextssl_profile_t profile;          /**< Active profile */
    
    /* Default algorithms for this profile */
    nextssl_hash_algo_t default_hash;
    nextssl_aead_algo_t default_aead;
    nextssl_kdf_algo_t default_kdf;
    nextssl_sign_algo_t default_sign;
    nextssl_kem_algo_t default_kem;
    
    /* Security flags */
    bool strict_mode;                   /**< Reject weak parameters */
    bool allow_legacy;                  /**< Allow legacy algorithms */
    bool pqc_only;                      /**< Require post-quantum */
    
    /* Metadata */
    uint32_t initialized;               /**< Magic value when init complete */
    const char *profile_name;           /**< Human-readable profile name */
} nextssl_config_t;

/* ========================================================================
 * CONFIGURATION API
 * ======================================================================== */

/**
 * @brief Initialize configuration with profile
 * 
 * Must be called once before using library.
 * Config becomes immutable after initialization.
 * 
 * @param profile Security profile to use
 * @return Pointer to immutable config, or NULL on error
 */
const nextssl_config_t* nextssl_config_init(nextssl_profile_t profile);

/**
 * @brief Get current active configuration
 * 
 * @return Pointer to immutable config, or NULL if not initialized
 */
const nextssl_config_t* nextssl_config_get(void);

/**
 * @brief Check if algorithm is available in current build
 * 
 * Validates algorithm against compile-time configuration.
 * 
 * @param algo_type Type of algorithm ("hash", "aead", "kdf", "sign", "kem")
 * @param algo_id Algorithm identifier
 * @return true if available, false otherwise
 */
bool nextssl_config_algo_available(const char *algo_type, int algo_id);

/**
 * @brief Get security level of current configuration
 * 
 * @return String describing security level ("modern-safe", "post-quantum", etc.)
 */
const char* nextssl_config_security_level(void);

/**
 * @brief Get profile name
 * 
 * @param profile Profile enum
 * @return Human-readable profile name
 */
const char* nextssl_config_profile_name(nextssl_profile_t profile);

/**
 * @brief Validate algorithm selection against current profile
 * 
 * Checks if algorithm is:
 * 1. Compiled into this variant (lite/full)
 * 2. Allowed by current profile
 * 3. Meets security requirements
 * 
 * @param algo_type Algorithm type
 * @param algo_id Algorithm identifier
 * @return 0 on success, negative error code otherwise
 */
int nextssl_config_validate_algo(const char *algo_type, int algo_id);

/**
 * @brief Initialize configuration, or return existing config if already initialized
 *
 * Unlike nextssl_config_init() which returns NULL on second call, this
 * auto-initializes to MODERN and returns the active config even if called
 * without an explicit nextssl_init(). Used internally by default-path functions.
 *
 * @return Pointer to immutable config, never NULL
 */
const nextssl_config_t* nextssl_config_get_or_default(void);

/**
 * @brief Reset configuration to uninitialized state
 *
 * Clears the magic guard so a subsequent nextssl_config_init() or
 * nextssl_config_init_custom() call is accepted.  Called by nextssl_cleanup().
 */
void nextssl_config_reset(void);

/* ========================================================================
 * CUSTOM PROFILE API
 * ======================================================================== */

/**
 * @brief Custom profile descriptor — fill before calling nextssl_config_init_custom()
 *
 * Set each field to the desired algorithm.  All five must be set unless you
 * supply a base profile via nextssl_config_init() first; this struct REPLACES
 * the active config entirely, it does not delta-patch it.
 *
 * Validation rules:
 *   - Every algorithm must be compiled into this build variant (lite vs full).
 *   - In NEXTSSL_BUILD_LITE, any full-only enum value (> the _MAX guards) is
 *     rejected with NEXTSSL_CONFIG_ERR_ALGO_UNAVAIL.
 *   - Config becomes immutable after a successful call, same as nextssl_config_init().
 */
typedef struct {
    nextssl_hash_algo_t  hash;   /**< e.g. NEXTSSL_HASH_SHA256, NEXTSSL_HASH_MD5 (full only) */
    nextssl_aead_algo_t  aead;   /**< e.g. NEXTSSL_AEAD_AES_256_GCM */
    nextssl_kdf_algo_t   kdf;    /**< e.g. NEXTSSL_KDF_ARGON2ID */
    nextssl_sign_algo_t  sign;   /**< e.g. NEXTSSL_SIGN_ED25519 */
    nextssl_kem_algo_t   kem;    /**< e.g. NEXTSSL_KEM_ML_KEM_1024 */
    const char          *name;   /**< Optional label shown by nextssl_config_profile_name() */
} nextssl_profile_custom_t;

/**
 * @brief Initialize configuration with a user-defined custom profile
 *
 * Validates that every selected algorithm is compiled into this build.
 * On success, config is locked — no further changes are possible.
 *
 * @param custom  Pointer to a fully-populated custom profile descriptor
 * @return Pointer to immutable config, or NULL on error (already init, invalid algo)
 */
const nextssl_config_t* nextssl_config_init_custom(const nextssl_profile_custom_t *custom);

/* Error codes */
#define NEXTSSL_CONFIG_SUCCESS           0
#define NEXTSSL_CONFIG_ERR_NOT_INIT     -1
#define NEXTSSL_CONFIG_ERR_ALREADY_INIT -2
#define NEXTSSL_CONFIG_ERR_INVALID_PROF -3
#define NEXTSSL_CONFIG_ERR_ALGO_UNAVAIL -4
#define NEXTSSL_CONFIG_ERR_ALGO_BLOCKED -5

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PROFILES_CONFIG_H */
