/**
 * @file hash.c
 * @brief Lite variant hash implementation (SHA-256, SHA-512, BLAKE3)
 */

#include "hash.h"
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"
#include <string.h>
#include <stdlib.h>

int nextssl_lite_hash(const char *algorithm, const uint8_t *data, size_t data_len, uint8_t *output) {
    if (!data || !output) {
        return -1;  // NEXTSSL_ERROR_INVALID_PARAMETER
    }
    
    // Default to SHA-256
    if (!algorithm || strcmp(algorithm, "SHA-256") == 0) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, data, data_len);
        sha256_final(&ctx, output);
        return 0;
    }
    
    if (strcmp(algorithm, "SHA-512") == 0) {
        SHA512_CTX ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, data, data_len);
        sha512_final(output, &ctx);  // Note: SHA512 has reversed argument order
        return 0;
    }
    
    if (strcmp(algorithm, "BLAKE3") == 0) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data, data_len);
        blake3_hasher_finalize(&hasher, output, 32);
        return 0;
    }
    
    return -2;  // NEXTSSL_ERROR_INVALID_ALGORITHM
}

int nextssl_lite_hash_size(const char *algorithm) {
    if (!algorithm || strcmp(algorithm, "SHA-256") == 0 || strcmp(algorithm, "BLAKE3") == 0) {
        return 32;
    }
    if (strcmp(algorithm, "SHA-512") == 0) {
        return 64;
    }
    return -1;
}

int nextssl_lite_hash_available(const char *algorithm) {
    if (!algorithm) return 0;
    if (strcmp(algorithm, "SHA-256") == 0) return 1;
    if (strcmp(algorithm, "SHA-512") == 0) return 1;
    if (strcmp(algorithm, "BLAKE3") == 0) return 1;
    return 0;
}

// Incremental hashing support (stub for now)
int nextssl_lite_hash_init(const char *algorithm, void **ctx) {
    return -99;  // NOT_IMPLEMENTED
}

int nextssl_lite_hash_update(void *ctx, const uint8_t *data, size_t len) {
    return -99;  // NOT_IMPLEMENTED
}

int nextssl_lite_hash_final(void *ctx, uint8_t *output) {
    return -99;  // NOT_IMPLEMENTED
}
