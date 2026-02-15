#include "primitive_sponge_xof.h"
#include "../../primitives/hash/sponge_xof/sha3/sha3.h"
#include "../../primitives/hash/sponge_xof/sha3_224/sha3_224.h"
#include "../../primitives/hash/sponge_xof/sha3_384/sha3_384.h"
#include "../../primitives/hash/sponge_xof/shake/shake.h"

int leyline_sha3_224(const uint8_t *msg, size_t len, uint8_t *out) {
    sha3_224_hash(msg, len, out);
    return 0;
}

int leyline_sha3_256(const uint8_t *msg, size_t len, uint8_t *out) {
    sha3_256_hash(msg, len, out);
    return 0;
}

int leyline_sha3_384(const uint8_t *msg, size_t len, uint8_t *out) {
    sha3_384_hash(msg, len, out);
    return 0;
}

int leyline_sha3_512(const uint8_t *msg, size_t len, uint8_t *out) {
    sha3_512_hash(msg, len, out);
    return 0;
}

int leyline_keccak_256(const uint8_t *msg, size_t len, uint8_t *out) {
    keccak_256_hash(msg, len, out);
    return 0;
}

int leyline_shake128(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len) {
    shake128_hash(msg, len, out, out_len);
    return 0;
}

int leyline_shake256(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len) {
    shake256_hash(msg, len, out, out_len);
    return 0;
}
