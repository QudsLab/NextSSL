/**
 * @file password.c
 * @brief Lite variant password/KDF implementation (Argon2id, HKDF)
 */

#include "password.h"
#include "../../../primitives/hash/memory_hard/Argon2id/argon2id.h"
#include "../../../PQCrypto/common/hkdf/hkdf.h"
#include "../../../PQCrypto/common/sha2.h"
#include <string.h>

#define NEXTSSL_LITE_ARGON2_DEFAULT_TIME 3
#define NEXTSSL_LITE_ARGON2_DEFAULT_MEMORY (64 * 1024)  // 64 MB
#define NEXTSSL_LITE_ARGON2_DEFAULT_PARALLELISM 4

int nextssl_lite_password_hash(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *output
) {
    if (!password || !salt || !output) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    if (salt_len < 16) {
        return -1;  // Salt too short (recommend 16 bytes min)
    }
    
    // Use Argon2id with default parameters (32 byte output)
    int result = argon2id_hash_raw(
        NEXTSSL_LITE_ARGON2_DEFAULT_TIME,       // t_cost
        NEXTSSL_LITE_ARGON2_DEFAULT_MEMORY,     // m_cost (in KB)
        NEXTSSL_LITE_ARGON2_DEFAULT_PARALLELISM, // parallelism
        password,                                // pwd
        password_len,                            // pwdlen
        salt,                                    // salt
        salt_len,                                // saltlen
        output,                                  // hash
        32                                       // hashlen (32 bytes fixed)
    );
    
    return (result == 0) ? 0 : -4;  // NEXTSSL_ERROR_CRYPTO_FAIL
}

int nextssl_lite_password_hash_custom(
    const char *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_cost_kb,
    uint32_t parallelism,
    uint8_t *output,
    size_t output_len
) {
    if (!password || !salt || !output) {
        return -1;
    }
    
    int result = argon2id_hash_raw(
        time_cost,          // t_cost
        memory_cost_kb,     // m_cost (in KB)
        parallelism,        // parallelism
        password,           // pwd
        password_len,       // pwdlen
        salt,               // salt
        salt_len,           // saltlen
        output,             // hash
        output_len          // hashlen
    );
    
    return (result == 0) ? 0 : -4;
}

int nextssl_lite_password_verify(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *expected_hash
) {
    if (!password || !salt || !expected_hash) {
        return -1;
    }
    
    uint8_t computed_hash[32];
    size_t hash_len = 32;
    
    int result = nextssl_lite_password_hash((const uint8_t *)password, password_len, salt, salt_len,
                                           computed_hash);
    if (result != 0) {
        return result;
    }
    
    // Constant-time comparison
    int diff = 0;
    for (size_t i = 0; i < hash_len; i++) {
        diff |= computed_hash[i] ^ expected_hash[i];
    }
    
    return (diff == 0) ? 0 : -5;  // NEXTSSL_ERROR_AUTH_FAIL
}

int nextssl_lite_kdf_derive(
    const uint8_t *input_key,
    size_t input_key_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *output_key,
    size_t output_key_len
) {
    if (!input_key || !output_key) {
        return -1;
    }
    
    // HKDF-SHA256 (use 'hkdf' which is SHA256-based)
    if (hkdf(salt, salt_len, input_key, input_key_len,
             info, info_len, output_key, output_key_len) != 0) {
        return -4;
    }
    
    return 0;
}
