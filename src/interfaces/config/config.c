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
    {NEXTSSL_HASH_SHA224, "SHA224", true},
    {NEXTSSL_HASH_SHA3_224, "SHA3-224", true},
    {NEXTSSL_HASH_SHA3_384, "SHA3-384", true},
    {NEXTSSL_HASH_KECCAK256, "KECCAK256", true},
    {NEXTSSL_HASH_SHAKE128, "SHAKE128", true},
    {NEXTSSL_HASH_SHAKE256, "SHAKE256", true},
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

/* PoW algorithms available in this build */
static const struct {
    nextssl_pow_algo_t id;
    const char *name;   /* dispatcher string ID */
    bool available;
} pow_algos[] = {
    {NEXTSSL_POW_SHA256,   "sha256",   true},
    {NEXTSSL_POW_SHA512,   "sha512",   true},
    {NEXTSSL_POW_BLAKE3,   "blake3",   true},
    {NEXTSSL_POW_ARGON2ID, "argon2id", true},

#ifndef NEXTSSL_BUILD_LITE
    {NEXTSSL_POW_SHA224,    "sha224",    true},
    {NEXTSSL_POW_SHA3_224,  "sha3_224",  true},
    {NEXTSSL_POW_SHA3_256,  "sha3_256",  true},
    {NEXTSSL_POW_SHA3_384,  "sha3_384",  true},
    {NEXTSSL_POW_SHA3_512,  "sha3_512",  true},
    {NEXTSSL_POW_KECCAK256, "keccak_256", true},
    {NEXTSSL_POW_SHAKE128,  "shake128",  true},
    {NEXTSSL_POW_SHAKE256,  "shake256",  true},
    {NEXTSSL_POW_BLAKE2B,   "blake2b",   true},
    {NEXTSSL_POW_BLAKE2S,   "blake2s",   true},
    {NEXTSSL_POW_ARGON2I,   "argon2i",   true},
    {NEXTSSL_POW_ARGON2D,   "argon2d",   true},
    {NEXTSSL_POW_MD5,       "md5",       true},
    {NEXTSSL_POW_SHA1,      "sha1",      true},
    {NEXTSSL_POW_RIPEMD160, "ripemd160", true},
    {NEXTSSL_POW_WHIRLPOOL, "whirlpool", true},
    {NEXTSSL_POW_NT,        "nt",        true},
    {NEXTSSL_POW_MD2,       "md2",       true},
    {NEXTSSL_POW_MD4,       "md4",       true},
    {NEXTSSL_POW_SHA0,      "sha0",      true},
    {NEXTSSL_POW_HAS160,    "has160",    true},
    {NEXTSSL_POW_RIPEMD128, "ripemd128", true},
    {NEXTSSL_POW_RIPEMD256, "ripemd256", true},
    {NEXTSSL_POW_RIPEMD320, "ripemd320", true},
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
    else if (strcmp(algo_type, "pow") == 0) {
        if (algo_id < 0 || algo_id >= NEXTSSL_POW_MAX) {
            return false;
        }
        for (size_t i = 0; i < sizeof(pow_algos) / sizeof(pow_algos[0]); i++) {
            if (pow_algos[i].id == algo_id) {
                return pow_algos[i].available;
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
    if (!nextssl_config_algo_available("pow",  (int)custom->pow))  return NULL;

    /* Build the config manually — NEXTSSL_PROFILE_MAX is the custom sentinel */
    g_config.profile      = NEXTSSL_PROFILE_MAX;
    g_config.default_hash = custom->hash;
    g_config.default_aead = custom->aead;
    g_config.default_kdf  = custom->kdf;
    g_config.default_sign = custom->sign;
    g_config.default_kem  = custom->kem;
    g_config.default_pow  = custom->pow;
    g_config.profile_name = (custom->name != NULL) ? custom->name : "Custom";
    /* Security flags — user explicitly chose algorithms, allow anything */
    g_config.strict_mode  = false;
    g_config.allow_legacy = true;
    g_config.pqc_only     = false;

    g_config.initialized = NEXTSSL_CONFIG_MAGIC;
    return &g_config;
}

const char* nextssl_pow_algo_id(nextssl_pow_algo_t algo) {
    if ((int)algo < 0 || algo >= NEXTSSL_POW_MAX) return NULL;
    for (size_t i = 0; i < sizeof(pow_algos) / sizeof(pow_algos[0]); i++) {
        if (pow_algos[i].id == algo) {
            return pow_algos[i].name;
        }
    }
    return NULL;
}

/* ========================================================================
 * PROFILE BUILDER
 * ======================================================================== */

/* Platform RAM query helpers */
#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
static uint64_t _available_ram_kb(void) {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return 131072; /* fallback 128 MB */
    return (uint64_t)(ms.ullAvailPhys / 1024);
}
static uint32_t _logical_cpu_count(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (uint32_t)si.dwNumberOfProcessors;
}
#elif defined(__unix__) || defined(__APPLE__)
#  include <unistd.h>
static uint64_t _available_ram_kb(void) {
    long pages     = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages < 0 || page_size < 0) return 131072; /* fallback 128 MB */
    return (uint64_t)((uint64_t)pages * (uint64_t)page_size / 1024);
}
static uint32_t _logical_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (uint32_t)n : 1;
}
#else
static uint64_t _available_ram_kb(void) { return 131072; }
static uint32_t _logical_cpu_count(void) { return 1; }
#endif

/* Argon2 profile defaults table indexed by profile */
static const nextssl_argon2_params_t _argon2_defaults[] = {
    /* MODERN / LEVEL_STANDARD  */  {4, 262144, 4, 32},
    /* COMPLIANCE               */  {4, 262144, 4, 32},
    /* PQC                      */  {4, 262144, 4, 32},
#ifndef NEXTSSL_BUILD_LITE
    /* COMPATIBILITY            */  {3,  65536, 4, 32},
    /* EMBEDDED                 */  {2,  32768, 1, 32},
    /* RESEARCH                 */  {4, 262144, 4, 32},
    /* LEVEL_HIGH               */  {4, 524288, 4, 48},
    /* LEVEL_MAX                */  {8,1048576, 8, 64},
#endif
};

nextssl_profile_builder_t nextssl_profile_builder_start(nextssl_profile_t base) {
    nextssl_profile_builder_t b;
    memset(&b, 0, sizeof(b));

    /* Load the base profile into the in-progress config */
    if (nextssl_profile_load(base, &b.cfg) != 0) {
        /* Unknown profile — fall back to MODERN */
        nextssl_profile_load(NEXTSSL_PROFILE_MODERN, &b.cfg);
    }

    /* Set Argon2 parameter defaults from table */
    int idx = (int)base;
    int tbl_sz = (int)(sizeof(_argon2_defaults) / sizeof(_argon2_defaults[0]));
    if (idx >= 0 && idx < tbl_sz) {
        b.cfg.argon2_params = _argon2_defaults[idx];
    } else {
        b.cfg.argon2_params = _argon2_defaults[0]; /* MODERN fallback */
    }

    /* Default salt */
    strncpy(b.cfg.default_salt, "NextSSL_Default_Salt",
            sizeof(b.cfg.default_salt) - 1);

    /* Default resource limits */
#ifdef NEXTSSL_BUILD_LITE
    b.cfg.max_argon2_wu = 8;
    b.cfg.max_argon2_mu = 65536;
#else
    b.cfg.max_argon2_wu = 32;
    b.cfg.max_argon2_mu = 2097152;
#endif

    /* Mark as not yet committed — initialized magic is NOT set */
    b.cfg.initialized = 0;
    b.committed       = false;
    return b;
}

void nextssl_profile_builder_set_hash(nextssl_profile_builder_t *b, nextssl_hash_algo_t algo) {
    if (b && !b->committed) b->cfg.default_hash = algo;
}
void nextssl_profile_builder_set_aead(nextssl_profile_builder_t *b, nextssl_aead_algo_t algo) {
    if (b && !b->committed) b->cfg.default_aead = algo;
}
void nextssl_profile_builder_set_kdf(nextssl_profile_builder_t *b, nextssl_kdf_algo_t algo) {
    if (b && !b->committed) b->cfg.default_kdf = algo;
}
void nextssl_profile_builder_set_sign(nextssl_profile_builder_t *b, nextssl_sign_algo_t algo) {
    if (b && !b->committed) b->cfg.default_sign = algo;
}
void nextssl_profile_builder_set_kem(nextssl_profile_builder_t *b, nextssl_kem_algo_t algo) {
    if (b && !b->committed) b->cfg.default_kem = algo;
}
void nextssl_profile_builder_set_pow(nextssl_profile_builder_t *b, nextssl_pow_algo_t algo) {
    if (b && !b->committed) b->cfg.default_pow = algo;
}
void nextssl_profile_builder_set_argon2(nextssl_profile_builder_t *b, const nextssl_argon2_params_t *p) {
    if (b && !b->committed && p) b->cfg.argon2_params = *p;
}
void nextssl_profile_builder_set_pow_params(nextssl_profile_builder_t *b, const nextssl_pow_params_t *p) {
    if (b && !b->committed && p) b->cfg.pow_params = *p;
}
void nextssl_profile_builder_set_salt(nextssl_profile_builder_t *b, const char *salt) {
    if (!b || b->committed || !salt) return;
    strncpy(b->cfg.default_salt, salt, sizeof(b->cfg.default_salt) - 1);
    b->cfg.default_salt[sizeof(b->cfg.default_salt) - 1] = '\0';
}
void nextssl_profile_builder_set_resource_limits(nextssl_profile_builder_t *b,
                                                  uint32_t max_wu, uint32_t max_mu) {
    if (b && !b->committed) {
        b->cfg.max_argon2_wu = max_wu;
        b->cfg.max_argon2_mu = max_mu;
    }
}
void nextssl_profile_builder_ignore_resource_check(nextssl_profile_builder_t *b) {
    if (b) b->ignore_resource_check = true;
}

const nextssl_config_t* nextssl_config_init_from_builder(nextssl_profile_builder_t *b) {
    if (!b || b->committed) return NULL;
    if (g_config.initialized == NEXTSSL_CONFIG_MAGIC) return NULL; /* already init */

    /* Validate every algorithm */
    if (!nextssl_config_algo_available("hash", (int)b->cfg.default_hash)) return NULL;
    if (!nextssl_config_algo_available("aead", (int)b->cfg.default_aead)) return NULL;
    if (!nextssl_config_algo_available("kdf",  (int)b->cfg.default_kdf))  return NULL;
    if (!nextssl_config_algo_available("sign", (int)b->cfg.default_sign)) return NULL;
    if (!nextssl_config_algo_available("kem",  (int)b->cfg.default_kem))  return NULL;
    if (!nextssl_config_algo_available("pow",  (int)b->cfg.default_pow))  return NULL;

    /* Legacy algo check: if any non-safe algo selected, clear strict_mode */
    /* (Simplified: if allow_legacy was not set but a legacy algo is used) */
    if (!b->cfg.allow_legacy) {
        if (b->cfg.default_hash == NEXTSSL_HASH_MD5 ||
            b->cfg.default_hash == NEXTSSL_HASH_SHA1) {
            fprintf(stderr, "[nextssl] WARNING: legacy hash selected; strict_mode disabled\n");
            b->cfg.strict_mode  = false;
            b->cfg.allow_legacy = true;
        }
    }

    /* Resource limit check */
    if (!b->ignore_resource_check &&
        (b->cfg.default_kdf == NEXTSSL_KDF_ARGON2ID ||
         b->cfg.default_kdf == NEXTSSL_KDF_ARGON2I  ||
         b->cfg.default_kdf == NEXTSSL_KDF_ARGON2D)) {

        uint32_t wu = b->cfg.argon2_params.time_cost;
        uint32_t mu = b->cfg.argon2_params.memory_cost_kb;

        /* Check declared resource limits */
        if (b->cfg.max_argon2_wu > 0 && wu > b->cfg.max_argon2_wu) return NULL;
        if (b->cfg.max_argon2_mu > 0 && mu > b->cfg.max_argon2_mu) return NULL;

        /* Check actual system resources */
        uint64_t avail_kb = _available_ram_kb();
        uint32_t cpu_cnt  = _logical_cpu_count();
        if (mu > 0 && (uint64_t)mu > avail_kb)        return NULL; /* NEXTSSL_CONFIG_ERR_RESOURCE_LIMIT */
        if (b->cfg.argon2_params.parallelism > cpu_cnt) return NULL;
    }

    /* Commit */
    b->cfg.initialized = NEXTSSL_CONFIG_MAGIC;
    b->cfg.profile_name = b->cfg.profile_name ? b->cfg.profile_name : "Custom";
    g_config   = b->cfg;
    b->committed = true;
    return &g_config;
}
