/**
 * @file config.c
 * @brief NextSSL Configuration Implementation
 * 
 * Immutable profile-based configuration with strict validation.
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#include "config.h"
#include "profiles/profiles.h"
#include <string.h>
#include <stdio.h>

/* Magic value to detect initialization */
#define NEXTSSL_CONFIG_MAGIC 0x4E535346  /* "NSSF" */

/* Global immutable config (initialized once) */
static nextssl_config_t g_config = {0};

/* ========================================================================
 * ALGORITHM AVAILABILITY TABLES (Compile-time validated)
 * ======================================================================== */

/* Hash algorithms available in this build */
static const struct {
    nextssl_hash_algo_t id;
    const char *name;
    bool available;
} hash_algos[] = {
    {NEXTSSL_HASH_SHA256, "SHA256", true},
    {NEXTSSL_HASH_SHA512, "SHA512", true},
    {NEXTSSL_HASH_BLAKE3, "BLAKE3", true},
    
#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_HASH_SHA384, "SHA384", true},
    {NEXTSSL_HASH_SHA1, "SHA1", true},
    {NEXTSSL_HASH_MD5, "MD5", true},
    {NEXTSSL_HASH_BLAKE2B, "BLAKE2B", true},
    {NEXTSSL_HASH_BLAKE2S, "BLAKE2S", true},
    {NEXTSSL_HASH_SHA3_256, "SHA3-256", true},
    {NEXTSSL_HASH_SHA3_512, "SHA3-512", true},
#endif
};

/* AEAD algorithms available in this build */
static const struct {
    nextssl_aead_algo_t id;
    const char *name;
    bool available;
} aead_algos[] = {
    {NEXTSSL_AEAD_AES_256_GCM, "AES-256-GCM", true},
    {NEXTSSL_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305", true},
    
#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_AEAD_AES_128_GCM, "AES-128-GCM", true},
    {NEXTSSL_AEAD_AES_256_CCM, "AES-256-CCM", true},
    {NEXTSSL_AEAD_AES_128_CCM, "AES-128-CCM", true},
    {NEXTSSL_AEAD_AEGIS_256, "AEGIS-256", true},
    {NEXTSSL_AEAD_XCHACHA20_POLY1305, "XChaCha20-Poly1305", true},
#endif
};

/* KDF algorithms available in this build */
static const struct {
    nextssl_kdf_algo_t id;
    const char *name;
    bool available;
} kdf_algos[] = {
    {NEXTSSL_KDF_HKDF_SHA256, "HKDF-SHA256", false},  /* TODO: Not implemented yet */
    {NEXTSSL_KDF_ARGON2ID, "Argon2id", true},
    
#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_KDF_HKDF_SHA512, "HKDF-SHA512", false},
    {NEXTSSL_KDF_ARGON2I, "Argon2i", true},
    {NEXTSSL_KDF_ARGON2D, "Argon2d", true},
    {NEXTSSL_KDF_SCRYPT, "scrypt", true},
    {NEXTSSL_KDF_PBKDF2, "PBKDF2", true},
#endif
};

/* Signature algorithms available in this build */
static const struct {
    nextssl_sign_algo_t id;
    const char *name;
    bool available;
} sign_algos[] = {
    {NEXTSSL_SIGN_ED25519, "Ed25519", true},
    {NEXTSSL_SIGN_ML_DSA_87, "ML-DSA-87", true},
    
#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_SIGN_ED448, "Ed448", true},
    {NEXTSSL_SIGN_ML_DSA_65, "ML-DSA-65", true},
    {NEXTSSL_SIGN_ML_DSA_44, "ML-DSA-44", true},
    {NEXTSSL_SIGN_FALCON_1024, "Falcon-1024", true},
    {NEXTSSL_SIGN_FALCON_512, "Falcon-512", true},
    {NEXTSSL_SIGN_SPHINCS_256F, "SPHINCS+-256f", true},
    {NEXTSSL_SIGN_ECDSA_P256, "ECDSA-P256", true},
    {NEXTSSL_SIGN_ECDSA_P384, "ECDSA-P384", true},
    {NEXTSSL_SIGN_RSA_3072_PSS, "RSA-3072-PSS", true},
#endif
};

/* KEM algorithms available in this build */
static const struct {
    nextssl_kem_algo_t id;
    const char *name;
    bool available;
} kem_algos[] = {
    {NEXTSSL_KEM_X25519, "X25519", false},  /* TODO: Not implemented yet */
    {NEXTSSL_KEM_ML_KEM_1024, "ML-KEM-1024", true},
    
#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_KEM_X448, "X448", false},
    {NEXTSSL_KEM_ML_KEM_768, "ML-KEM-768", true},
    {NEXTSSL_KEM_ML_KEM_512, "ML-KEM-512", true},
    {NEXTSSL_KEM_HQC_256, "HQC-256", true},
    {NEXTSSL_KEM_BIKE_L5, "BIKE-L5", true},
    {NEXTSSL_KEM_ECDH_P256, "ECDH-P256", true},
    {NEXTSSL_KEM_ECDH_P384, "ECDH-P384", true},
#endif
};

/* ========================================================================
 * CONFIGURATION API IMPLEMENTATION
 * ======================================================================== */

const nextssl_config_t* nextssl_config_init(nextssl_profile_t profile) {
    /* Check if already initialized */
    if (g_config.initialized == NEXTSSL_CONFIG_MAGIC) {
        return NULL;  /* Already initialized */
    }
    
    /* Validate profile availability */
#ifdef NEXTSSL_BUILD_LITE
    if (profile != NEXTSSL_PROFILE_MODERN && 
        profile != NEXTSSL_PROFILE_COMPLIANCE && 
        profile != NEXTSSL_PROFILE_PQC) {
        return NULL;  /* Profile not available in lite variant */
    }
#endif
    
    if (profile >= NEXTSSL_PROFILE_MAX) {
        return NULL;  /* Invalid profile */
    }
    
    /* Load profile configuration */
    nextssl_profile_load(profile, &g_config);
    
    /* Mark as initialized */
    g_config.initialized = NEXTSSL_CONFIG_MAGIC;
    
    return &g_config;
}

const nextssl_config_t* nextssl_config_get(void) {
    if (g_config.initialized != NEXTSSL_CONFIG_MAGIC) {
        return NULL;  /* Not initialized */
    }
    return &g_config;
}

void nextssl_config_reset(void) {
    g_config.initialized = 0;  /* Clear magic — allows re-init */
}

bool nextssl_config_algo_available(const char *algo_type, int algo_id) {
    if (algo_type == NULL) {
        return false;
    }
    
    if (strcmp(algo_type, "hash") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_HASH_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(hash_algos) / sizeof(hash_algos[0]); i++) {
            if (hash_algos[i].id == algo_id) {
                return hash_algos[i].available;
            }
        }
    }
    else if (strcmp(algo_type, "aead") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_AEAD_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(aead_algos) / sizeof(aead_algos[0]); i++) {
            if (aead_algos[i].id == algo_id) {
                return aead_algos[i].available;
            }
        }
    }
    else if (strcmp(algo_type, "kdf") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_KDF_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(kdf_algos) / sizeof(kdf_algos[0]); i++) {
            if (kdf_algos[i].id == algo_id) {
                return kdf_algos[i].available;
            }
        }
    }
    else if (strcmp(algo_type, "sign") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_SIGN_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(sign_algos) / sizeof(sign_algos[0]); i++) {
            if (sign_algos[i].id == algo_id) {
                return sign_algos[i].available;
            }
        }
    }
    else if (strcmp(algo_type, "kem") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_KEM_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(kem_algos) / sizeof(kem_algos[0]); i++) {
            if (kem_algos[i].id == algo_id) {
                return kem_algos[i].available;
            }
        }
    }
    
    return false;
}

const char* nextssl_config_security_level(void) {
    const nextssl_config_t *cfg = nextssl_config_get();
    if (cfg == NULL) {
        return "uninitialized";
    }
    
    switch (cfg->profile) {
        case NEXTSSL_PROFILE_MODERN:
            return "modern-safe";
        case NEXTSSL_PROFILE_COMPLIANCE:
            return "compliance-safe";
        case NEXTSSL_PROFILE_PQC:
            return "post-quantum";
#ifndef NEXTSSL_BUILD_LITE
        case NEXTSSL_PROFILE_COMPATIBILITY:
            return "compatibility";
        case NEXTSSL_PROFILE_EMBEDDED:
            return "embedded";
        case NEXTSSL_PROFILE_RESEARCH:
            return "research-experimental";
#endif
        case NEXTSSL_PROFILE_MAX:  /* sentinel used for custom profiles */
            return "custom";
        default:
            return "unknown";
    }
}

const char* nextssl_config_profile_name(nextssl_profile_t profile) {
    switch (profile) {
        case NEXTSSL_PROFILE_MODERN:
            return "Modern";
        case NEXTSSL_PROFILE_COMPLIANCE:
            return "Compliance";
        case NEXTSSL_PROFILE_PQC:
            return "Post-Quantum";
#ifndef NEXTSSL_BUILD_LITE
        case NEXTSSL_PROFILE_COMPATIBILITY:
            return "Compatibility";
        case NEXTSSL_PROFILE_EMBEDDED:
            return "Embedded";
        case NEXTSSL_PROFILE_RESEARCH:
            return "Research";
#endif
        default:
            return "Unknown";
    }
}

int nextssl_config_validate_algo(const char *algo_type, int algo_id) {
    const nextssl_config_t *cfg = nextssl_config_get();
    if (cfg == NULL) {
        return NEXTSSL_CONFIG_ERR_NOT_INIT;
    }
    
    /* Check if algorithm is compiled into this build */
    if (!nextssl_config_algo_available(algo_type, algo_id)) {
        return NEXTSSL_CONFIG_ERR_ALGO_UNAVAIL;
    }
    
    /* Check if algorithm is allowed by current profile */
    /* In strict mode, reject legacy algorithms */
    if (cfg->strict_mode && !cfg->allow_legacy) {
        if (strcmp(algo_type, "hash") == 0) {
#ifndef NEXTSSL_BUILD_LITE
            if (algo_id == NEXTSSL_HASH_SHA1 || algo_id == NEXTSSL_HASH_MD5) {
                return NEXTSSL_CONFIG_ERR_ALGO_BLOCKED;
            }
#endif
        }
    }
    
    /* In PQC-only mode, require post-quantum algorithms */
    if (cfg->pqc_only) {
        if (strcmp(algo_type, "sign") == 0) {
#ifndef NEXTSSL_BUILD_LITE
            if (algo_id == NEXTSSL_SIGN_ED25519 || algo_id == NEXTSSL_SIGN_ED448) {
#else
            if (algo_id == NEXTSSL_SIGN_ED25519) {
#endif
                return NEXTSSL_CONFIG_ERR_ALGO_BLOCKED;  /* Classical only */
            }
        }
        if (strcmp(algo_type, "kem") == 0) {
#ifndef NEXTSSL_BUILD_LITE
            if (algo_id == NEXTSSL_KEM_X25519 || algo_id == NEXTSSL_KEM_X448) {
#else
            if (algo_id == NEXTSSL_KEM_X25519) {
#endif
                return NEXTSSL_CONFIG_ERR_ALGO_BLOCKED;  /* Classical only */
            }
        }
    }
    
    return NEXTSSL_CONFIG_SUCCESS;
}

/* ========================================================================
 * EXTENDED API
 * ======================================================================== */

const nextssl_config_t* nextssl_config_get_or_default(void) {
    if (g_config.initialized == NEXTSSL_CONFIG_MAGIC) {
        return &g_config;
    }
    /* Auto-initialise to MODERN so default-path callers always get a config */
    return nextssl_config_init(NEXTSSL_PROFILE_MODERN);
}

const nextssl_config_t* nextssl_config_init_custom(const nextssl_profile_custom_t *custom) {
    if (custom == NULL) {
        return NULL;
    }
    if (g_config.initialized == NEXTSSL_CONFIG_MAGIC) {
        return NULL;  /* already initialized — config is immutable */
    }

    /* Validate every algorithm against compile-time availability tables.
     * In NEXTSSL_BUILD_LITE the full-only enum symbols don't exist, but a
     * caller could still pass their numeric value — the availability check
     * will reject them because they are not in the lite table. */
    if (!nextssl_config_algo_available("hash", (int)custom->hash)) return NULL;
    if (!nextssl_config_algo_available("aead", (int)custom->aead)) return NULL;
    if (!nextssl_config_algo_available("kdf",  (int)custom->kdf))  return NULL;
    if (!nextssl_config_algo_available("sign", (int)custom->sign)) return NULL;
    if (!nextssl_config_algo_available("kem",  (int)custom->kem))  return NULL;

    /* Build the config manually — NEXTSSL_PROFILE_MAX is the custom sentinel */
    g_config.profile      = NEXTSSL_PROFILE_MAX;
    g_config.default_hash = custom->hash;
    g_config.default_aead = custom->aead;
    g_config.default_kdf  = custom->kdf;
    g_config.default_sign = custom->sign;
    g_config.default_kem  = custom->kem;
    g_config.profile_name = (custom->name != NULL) ? custom->name : "Custom";
    /* Security flags — user explicitly chose algorithms, allow anything */
    g_config.strict_mode  = false;
    g_config.allow_legacy = true;
    g_config.pqc_only     = false;

    g_config.initialized = NEXTSSL_CONFIG_MAGIC;
    return &g_config;
}
