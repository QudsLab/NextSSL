#include "pow_primitive_sponge_xof.h"
#include "../../../primitives/hash/sponge_xof/keccak/keccak.h"
#include "../../../primitives/hash/sponge_xof/sha3/sha3.h"
#include "../../../primitives/hash/sponge_xof/shake/shake.h"

int pow_hash_keccak256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    // Uses SHA3_CTX structure for Keccak256 as defined in sha3.h
    SHA3_CTX kctx;
    keccak_256_init(&kctx);
    sha3_update(&kctx, msg, msg_len);
    if (nonce && nonce_len > 0) {
        sha3_update(&kctx, nonce, nonce_len);
    }
    sha3_final(out_hash, &kctx);
    return 0;
}

int pow_hash_sha3_256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    SHA3_CTX s3ctx;
    sha3_256_init(&s3ctx);
    sha3_update(&s3ctx, msg, msg_len);
    if (nonce && nonce_len > 0) {
        sha3_update(&s3ctx, nonce, nonce_len);
    }
    sha3_final(out_hash, &s3ctx);
    return 0;
}

int pow_hash_shake256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    SHAKE_CTX skctx;
    shake256_init(&skctx);
    shake_update(&skctx, msg, msg_len);
    if (nonce && nonce_len > 0) {
        shake_update(&skctx, nonce, nonce_len);
    }
    shake_final(&skctx);
    shake_squeeze(&skctx, out_hash, out_len);
    return 0;
}
