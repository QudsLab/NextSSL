/**
 * @file nextssl.c
 * @brief Lite variant unified API implementation (Layer 4)
 *
 * Delegates to main/lite Layer 3 for AEAD, key-exchange, and signatures.
 * Uses hash and Argon2id primitives directly to avoid function-name conflicts
 * with the same-named but differently-signatured main/lite hash and password
 * dispatchers.
 */

/* Mark this translation unit as building the DLL so NEXTSSL_API = dllexport */
#ifndef NEXTSSL_BUILDING_DLL
#  define NEXTSSL_BUILDING_DLL
#endif

#include "nextssl.h"

/*
 * Non-conflicting main/lite Layer-3 modules.
 * (main/lite/hash.h and main/lite/password.h are intentionally excluded;
 *  they declare nextssl_hash / nextssl_password_hash with different signatures
 *  than the three-arg / four-arg versions this file provides.)
 */
#include "../../main/lite/aead.h"
#include "../../main/lite/keyexchange.h"
#include "../../main/lite/signature.h"

/* Hash primitives used directly */
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"

/* Password-hash primitive (Argon2id) */
#include "../../../primitives/hash/memory_hard/Argon2id/argon2id.h"

/* OS-backed CSPRNG */
#include "../../../seed/rng/rng.h"

/* Profile-based configuration system */
#include "../../../config/config.h"
#include <string.h>

// ============================================================================
// Hash Functions (use primitives directly to avoid naming conflict with
// main/lite nextssl_hash which takes an extra leading algorithm argument)
// ============================================================================

NEXTSSL_API int nextssl_hash(const uint8_t *data, size_t len, uint8_t *output) {
    const nextssl_config_t *cfg = nextssl_config_get_or_default();
    switch (cfg->default_hash) {
        case NEXTSSL_HASH_SHA512: {
            sha512_hash(data, len, output);
            return 0;
        }
        case NEXTSSL_HASH_BLAKE3: {
            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, data, len);
            blake3_hasher_finalize(&h, output, BLAKE3_OUT_LEN);
            return 0;
        }
        case NEXTSSL_HASH_SHA256:
        default:
            sha256(data, len, output);
            return 0;
    }
}

NEXTSSL_API int nextssl_hash_ex(const char *algorithm, const uint8_t *data, size_t len, uint8_t *output) {
    if (!algorithm) {
        sha256(data, len, output);
        return 0;
    }
    if (strcmp(algorithm, "SHA-512") == 0) {
        sha512_hash(data, len, output);
        return 0;
    }
    if (strcmp(algorithm, "BLAKE3") == 0) {
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, data, len);
        blake3_hasher_finalize(&h, output, BLAKE3_OUT_LEN);
        return 0;
    }
    /* SHA-256 and unknown algorithms fall through to SHA-256 */
    sha256(data, len, output);
    return 0;
}

// ============================================================================
// Encryption Functions (delegates to main/lite aead)
// ============================================================================

static const char* _lite_aead_name(void) {
    const nextssl_config_t *cfg = nextssl_config_get_or_default();
    return (cfg->default_aead == NEXTSSL_AEAD_CHACHA20_POLY1305)
               ? "ChaCha20-Poly1305"
               : "AES-256-GCM";
}

NEXTSSL_API int nextssl_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
) {
    return nextssl_aead_encrypt(_lite_aead_name(), key, nonce, NULL, 0, plaintext, plen, ciphertext);
}

NEXTSSL_API int nextssl_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
) {
    return nextssl_aead_decrypt(_lite_aead_name(), key, nonce, NULL, 0, ciphertext, clen, plaintext);
}

NEXTSSL_API int nextssl_encrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
) {
    return nextssl_aead_encrypt(algorithm, key, nonce, NULL, 0, plaintext, plen, ciphertext);
}

NEXTSSL_API int nextssl_decrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
) {
    return nextssl_aead_decrypt(algorithm, key, nonce, NULL, 0, ciphertext, clen, plaintext);
}

// ============================================================================
// Password Hashing (Argon2id primitive — avoids salt_len conflict with
// main/lite nextssl_password_hash which takes an extra salt_len argument)
// ============================================================================

NEXTSSL_API int nextssl_password_hash(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    uint8_t *output
) {
    /* salt is documented as exactly 16 bytes; hash output is 32 bytes */
    return argon2id_hash_raw(3, 65536, 4, password, plen, salt, 16, output, 32);
}

NEXTSSL_API int nextssl_password_verify(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    const uint8_t *expected_hash
) {
    uint8_t computed[32];
    int ret = argon2id_hash_raw(3, 65536, 4, password, plen, salt, 16, computed, 32);
    if (ret != 0) return ret;
    /* Constant-time comparison */
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned)(computed[i] ^ expected_hash[i]);
    /* Zero the temporary hash buffer before returning */
    volatile uint8_t *p = computed;
    for (int i = 0; i < 32; i++) p[i] = 0;
    return (diff == 0) ? 0 : -1;
}

// ============================================================================
// Key Exchange (delegates to main/lite keyexchange)
// ============================================================================

NEXTSSL_API int nextssl_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_kyber1024_keygen(public_key, secret_key);
    } else {
        return nextssl_x25519_keygen(public_key, secret_key);
    }
}

NEXTSSL_API int nextssl_keyexchange(
    const uint8_t *my_secret,
    const uint8_t *their_public,
    uint8_t *shared_secret,
    uint8_t *ciphertext,
    int pqc
) {
    if (pqc) {
        if (!ciphertext) return -1;
        return nextssl_kyber1024_encaps(their_public, ciphertext, shared_secret);
    } else {
        return nextssl_x25519_exchange(my_secret, their_public, shared_secret);
    }
}

NEXTSSL_API int nextssl_keyexchange_decaps(
    const uint8_t *ciphertext,
    const uint8_t *my_secret,
    uint8_t *shared_secret
) {
    return nextssl_kyber1024_decaps(ciphertext, my_secret, shared_secret);
}

// ============================================================================
// Digital Signatures (delegates to main/lite signature)
// ============================================================================

NEXTSSL_API int nextssl_sign_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_dilithium5_keygen(public_key, secret_key);
    } else {
        return nextssl_ed25519_keygen(public_key, secret_key);
    }
}

NEXTSSL_API int nextssl_sign(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *secret_key,
    uint8_t *signature,
    int pqc
) {
    if (pqc) {
        size_t sig_len;
        return nextssl_dilithium5_sign(message, mlen, secret_key, signature, &sig_len);
    } else {
        return nextssl_ed25519_sign(message, mlen, secret_key, signature);
    }
}

NEXTSSL_API int nextssl_verify(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *signature,
    const uint8_t *public_key,
    int pqc
) {
    if (pqc) {
        return nextssl_dilithium5_verify(message, mlen, signature, NEXTSSL_DILITHIUM5_SIGNATURE_SIZE, public_key);
    } else {
        return nextssl_ed25519_verify(message, mlen, signature, public_key);
    }
}

// ============================================================================
// Proof-of-Work (sha256 primitive — avoids struct-signature conflict with
// main/lite nextssl_pow_solve which takes challenge/solution structs)
// ============================================================================

static int _leading_zero_bits(const uint8_t *hash) {
    int bits = 0;
    for (int i = 0; i < 32; i++) {
        if (hash[i] == 0) {
            bits += 8;
        } else {
            uint8_t b = hash[i];
            while (!(b & 0x80)) { bits++; b = (uint8_t)(b << 1); }
            break;
        }
    }
    return bits;
}

NEXTSSL_API int nextssl_pow_solve(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t *nonce,
    uint8_t *hash_output
) {
    if (!challenge_data || !nonce || !hash_output || challenge_len > 32) return -1;

    uint8_t buf[40];
    uint8_t hash[32];
    size_t clen = challenge_len;
    memcpy(buf, challenge_data, clen);

    for (uint64_t n = 0; ; n++) {
        memcpy(buf + clen, &n, 8);
        sha256(buf, clen + 8, hash);
        if ((uint32_t)_leading_zero_bits(hash) >= difficulty) {
            *nonce = n;
            memcpy(hash_output, hash, 32);
            return 0;
        }
    }
}

NEXTSSL_API int nextssl_pow_verify(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t nonce,
    const uint8_t *hash
) {
    if (!challenge_data || !hash || challenge_len > 32) return -1;

    uint8_t buf[40];
    uint8_t computed[32];
    size_t clen = challenge_len;
    memcpy(buf, challenge_data, clen);
    memcpy(buf + clen, &nonce, 8);
    sha256(buf, clen + 8, computed);

    if ((uint32_t)_leading_zero_bits(computed) < difficulty) return -1;

    /* Constant-time compare of recomputed vs supplied hash */
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned)(computed[i] ^ hash[i]);
    return (diff == 0) ? 0 : -1;
}

// ============================================================================
// Utility Functions
// ============================================================================

NEXTSSL_API int nextssl_random(uint8_t *output, size_t len) {
    return rng_fill(output, len);
}

NEXTSSL_API const char* nextssl_version(void) {
    return "NextSSL v0.1.0-beta-lite";
}

NEXTSSL_API const char* nextssl_variant(void) {
    return "lite";
}

NEXTSSL_API const char* nextssl_security_level(void) {
    return nextssl_config_security_level();
}

NEXTSSL_API int nextssl_has_algorithm(const char *algorithm) {
    if (!algorithm) return 0;
    /* Hash */
    if (strcmp(algorithm, "SHA-256") == 0 ||
        strcmp(algorithm, "SHA-512") == 0 ||
        strcmp(algorithm, "BLAKE3")  == 0) return 1;
    /* AEAD */
    if (strcmp(algorithm, "AES-256-GCM") == 0 ||
        strcmp(algorithm, "ChaCha20-Poly1305") == 0) return 1;
    /* KDF */
    if (strcmp(algorithm, "Argon2id") == 0 ||
        strcmp(algorithm, "HKDF")     == 0) return 1;
    /* Key exchange */
    if (strcmp(algorithm, "X25519")      == 0 ||
        strcmp(algorithm, "Kyber1024")   == 0 ||
        strcmp(algorithm, "ML-KEM-1024") == 0) return 1;
    /* Signatures */
    if (strcmp(algorithm, "Ed25519")    == 0 ||
        strcmp(algorithm, "Dilithium5") == 0 ||
        strcmp(algorithm, "ML-DSA-87")  == 0) return 1;
    return 0;
}

NEXTSSL_API int nextssl_list_algorithms(char *buffer, size_t size) {
    const char *algos = "SHA-256,SHA-512,BLAKE3,AES-256-GCM,ChaCha20-Poly1305,"
                        "Argon2id,HKDF,X25519,ML-KEM-1024,Ed25519,ML-DSA-87";
    if (buffer && size > 0) {
        size_t n = strlen(algos);
        if (n >= size) n = size - 1;
        memcpy(buffer, algos, n);
        buffer[n] = '\0';
    }
    return 9;
}

/*
 * nextssl_init(profile)
 *
 * profile: 0 = MODERN (default, SHA-256 / AES-256-GCM / Ed25519 / X25519)
 *           1 = COMPLIANCE (FIPS/NIST aligned)
 *           2 = PQC (BLAKE3 / ML-DSA-87 / ML-KEM-1024, post-quantum only)
 *
 * Config is immutable after the first successful call.
 * Calling again returns 0 (already initialized) without error.
 */
NEXTSSL_API int nextssl_init(int profile) {
    if ((unsigned)profile >= (unsigned)NEXTSSL_PROFILE_MAX) {
        profile = NEXTSSL_PROFILE_MODERN;
    }
    /* Lite only supports the three common profiles */
    if (profile != NEXTSSL_PROFILE_MODERN &&
        profile != NEXTSSL_PROFILE_COMPLIANCE &&
        profile != NEXTSSL_PROFILE_PQC) {
        return -1;  /* Profile not available in lite */
    }
    const nextssl_config_t *cfg = nextssl_config_init((nextssl_profile_t)profile);
    /* NULL means already initialized — that is not an error here */
    return (cfg != NULL || nextssl_config_get() != NULL) ? 0 : -1;
}

NEXTSSL_API int nextssl_init_custom(const nextssl_custom_profile_t *profile) {
    if (profile == NULL) return -1;
    nextssl_profile_custom_t internal;
    internal.hash  = (nextssl_hash_algo_t)profile->hash;
    internal.aead  = (nextssl_aead_algo_t)profile->aead;
    internal.kdf   = (nextssl_kdf_algo_t)profile->kdf;
    internal.sign  = (nextssl_sign_algo_t)profile->sign;
    internal.kem   = (nextssl_kem_algo_t)profile->kem;
    internal.pow   = (nextssl_pow_algo_t)profile->pow;
    internal.name  = profile->name;
    const nextssl_config_t *cfg = nextssl_config_init_custom(&internal);
    if (cfg == NULL) {
        /* Check if already initialized (not an error) vs invalid algo */
        return (nextssl_config_get() != NULL) ? -2 : -3;
    }
    return 0;
}

NEXTSSL_API void nextssl_cleanup(void) {
    /* Reset config so a subsequent nextssl_init() is accepted */
    nextssl_config_reset();
}
