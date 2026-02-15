#include "pow_server.h"
#include "core/pow_primitive_fast.h"
#include "core/pow_primitive_memory_hard.h"
#include "core/pow_primitive_sponge_xof.h"
#include "core/pow_legacy_alive.h"
#include <string.h>

static size_t pow_default_out_len(PoWAlgorithm algo) {
    switch (algo) {
        case POW_ALGO_BLAKE3: return 32;
        case POW_ALGO_SHA256: return 32;
        case POW_ALGO_SHA3_256: return 32;
        case POW_ALGO_ARGON2ID: return 32;
        case POW_ALGO_MD5: return 16;
        case POW_ALGO_SHA1: return 20;
        default: return 32;
    }
}

static int pow_server_hash(const PoWChallenge *c, const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len) {
    switch (c->algo) {
        case POW_ALGO_BLAKE3:
            return pow_hash_blake3(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
        case POW_ALGO_SHA256:
            return pow_hash_sha256(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
        case POW_ALGO_SHA3_256:
            return pow_hash_sha3_256(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
        case POW_ALGO_MD5:
            return pow_hash_md5(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
        case POW_ALGO_SHA1:
            return pow_hash_sha1(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
        case POW_ALGO_ARGON2ID: {
            Argon2Ctx ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.t_cost = c->argon2_t_cost > 0 ? c->argon2_t_cost : 1;
            ctx.m_cost_kb = c->argon2_m_cost_kb > 0 ? c->argon2_m_cost_kb : (c->max_memory_kb > 0 ? c->max_memory_kb : 1024);
            ctx.parallelism = c->argon2_parallelism > 0 ? c->argon2_parallelism : 1;
            ctx.encoded_len = c->argon2_encoded_len;
            return pow_hash_argon2id(msg, msg_len, nonce, nonce_len, out_hash, out_len, &ctx);
        }
        default:
            return -1;
    }
}

int pow_server_verify(const PoWChallenge *c, const uint8_t *nonce, size_t nonce_len, uint32_t input_index) {
    if (!c || input_index >= c->num_inputs) return 0;
    
    size_t hash_out_len = c->hash_out_len > 0 ? c->hash_out_len : pow_default_out_len(c->algo);
    if (hash_out_len > 64) return 0;

    uint8_t hash[64];
    if (pow_server_hash(c, c->inputs[input_index], c->input_lens[input_index], nonce, nonce_len, hash, hash_out_len) != 0) return 0;

    for (uint32_t i = 0; i < c->num_targets; i++) {
        if (c->targets[i].prefix_len > 0) {
            uint32_t diff = c->targets[i].difficulty > 0 ? c->targets[i].difficulty : 1;
            size_t required_len = c->targets[i].prefix_len * diff;
            if (required_len > hash_out_len) continue;
            int match = 1;
            for (uint32_t r = 0; r < diff; r++) {
                if (memcmp(hash + (r * c->targets[i].prefix_len), c->targets[i].prefix, c->targets[i].prefix_len) != 0) {
                    match = 0;
                    break;
                }
            }
            if (match) return 1;
        }
        // Numeric TODO
    }

    return 0;
}
