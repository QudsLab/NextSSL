#include "legacy_unsafe.h"
#include "../../legacy/unsafe/md4/md4.h"
#include "../../legacy/unsafe/md2/md2.h"
#include "../../legacy/unsafe/sha0/sha0.h"
#include "../../legacy/unsafe/ripemd128/ripemd128.h"
#include "../../legacy/unsafe/ripemd256/ripemd256.h"
#include "../../legacy/unsafe/ripemd320/ripemd320.h"
#include "../../legacy/unsafe/has160/has160.h"

int nextssl_md4(const uint8_t *msg, size_t len, uint8_t *out) {
    md4_hash(msg, len, out);
    return 0;
}

int nextssl_md2(const uint8_t *msg, size_t len, uint8_t *out) {
    md2_hash(msg, len, out);
    return 0;
}

int nextssl_sha0(const uint8_t *msg, size_t len, uint8_t *out) {
    sha0_hash(msg, len, out);
    return 0;
}

int nextssl_ripemd128(const uint8_t *msg, size_t len, uint8_t *out) {
    ripemd128_hash(msg, len, out);
    return 0;
}

int nextssl_ripemd256(const uint8_t *msg, size_t len, uint8_t *out) {
    ripemd256_hash(msg, len, out);
    return 0;
}

int nextssl_ripemd320(const uint8_t *msg, size_t len, uint8_t *out) {
    ripemd320_hash(msg, len, out);
    return 0;
}

int nextssl_has160(const uint8_t *msg, size_t len, uint8_t *out) {
    has160_hash(msg, len, out);
    return 0;
}
