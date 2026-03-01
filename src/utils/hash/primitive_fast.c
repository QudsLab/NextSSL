#include "primitive_fast.h"
#include "../../primitives/hash/fast/sha224/sha224.h"
#include "../../primitives/hash/fast/sha256/sha256.h"
#include "../../primitives/hash/fast/sha512/sha512.h"
#include "../../primitives/hash/fast/blake3/blake3.h"
#include "../../primitives/hash/fast/blake2b/blake2b.h"
#include "../../primitives/hash/fast/blake2s/blake2s.h"

int nextssl_sha224(const uint8_t *msg, size_t len, uint8_t *out) {
    sha224_hash(msg, len, out);
    return 0;
}

int nextssl_sha256(const uint8_t *msg, size_t len, uint8_t *out) {
    sha256(msg, len, out);
    return 0;
}

int nextssl_sha384(const uint8_t *msg, size_t len, uint8_t *out) {
    sha384_hash(msg, len, out);
    return 0;
}

int nextssl_sha512(const uint8_t *msg, size_t len, uint8_t *out) {
    sha512_hash(msg, len, out);
    return 0;
}

int nextssl_blake3(const uint8_t *msg, size_t len, uint8_t *out) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, msg, len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
    return 0;
}

int nextssl_blake2b(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len) {
    BLAKE2B_CTX ctx;
    blake2b_init(&ctx, out_len);
    blake2b_update(&ctx, msg, len);
    blake2b_final(&ctx, out, out_len);
    return 0;
}

int nextssl_blake2s(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len) {
    BLAKE2S_CTX ctx;
    blake2s_init(&ctx, out_len);
    blake2s_update(&ctx, msg, len);
    blake2s_final(&ctx, out, out_len);
    return 0;
}
