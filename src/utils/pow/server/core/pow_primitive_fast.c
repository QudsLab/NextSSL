#include "pow_primitive_fast.h"
#include "pow_dispatch.h"
#include "pow_primitive_memory_hard.h"
#include "pow_primitive_sponge_xof.h"
#include "pow_legacy_alive.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"
#include "../../../primitives/hash/fast/sha256/sha256.h"

int pow_hash_blake3(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, msg, msg_len);
    if (nonce && nonce_len > 0) {
        blake3_hasher_update(&hasher, nonce, nonce_len);
    }
    blake3_hasher_finalize(&hasher, out_hash, out_len);
    return 0;
}

int pow_hash_sha256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, msg, msg_len);
    if (nonce && nonce_len > 0) {
        sha256_update(&sha_ctx, nonce, nonce_len);
    }
    sha256_final(&sha_ctx, out_hash);
    return 0;
}

// Dispatcher Implementation
PoW_HashFunc pow_get_hash_func(PoWAlgorithm algo) {
    switch (algo) {
        case POW_ALGO_BLAKE3: return pow_hash_blake3;
        case POW_ALGO_SHA256: return pow_hash_sha256;
        case POW_ALGO_SHA3_256: return pow_hash_sha3_256;
        case POW_ALGO_ARGON2ID: return pow_hash_argon2id;
        case POW_ALGO_MD5: return pow_hash_md5;
        case POW_ALGO_SHA1: return pow_hash_sha1;
        default: return NULL;
    }
}
