#include "pow_legacy_unsafe.h"
#include "../../../legacy/unsafe/md2/md2.h"
#include "../../../legacy/unsafe/md4/md4.h"
#include "../../../legacy/unsafe/sha0/sha0.h"
#include "../../../legacy/unsafe/ripemd128/ripemd128.h"
#include "../../../legacy/unsafe/ripemd256/ripemd256.h"
#include "../../../legacy/unsafe/ripemd320/ripemd320.h"
#include "../../../legacy/unsafe/has160/has160.h"

int pow_hash_md2(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < MD2_DIGEST_LENGTH) return -1;
    MD2_CTX ctx_md2;
    md2_init(&ctx_md2);
    md2_update(&ctx_md2, msg, msg_len);
    if (nonce && nonce_len > 0) md2_update(&ctx_md2, nonce, nonce_len);
    md2_final(out_hash, &ctx_md2);
    return 0;
}

int pow_hash_md4(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < MD4_DIGEST_LENGTH) return -1;
    MD4_CTX ctx_md4;
    md4_init(&ctx_md4);
    md4_update(&ctx_md4, msg, msg_len);
    if (nonce && nonce_len > 0) md4_update(&ctx_md4, nonce, nonce_len);
    md4_final(out_hash, &ctx_md4);
    return 0;
}

int pow_hash_sha0(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < SHA0_DIGEST_LENGTH) return -1;
    SHA0_CTX ctx_sha0;
    sha0_init(&ctx_sha0);
    sha0_update(&ctx_sha0, msg, msg_len);
    if (nonce && nonce_len > 0) sha0_update(&ctx_sha0, nonce, nonce_len);
    sha0_final(out_hash, &ctx_sha0);
    return 0;
}

int pow_hash_ripemd128(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < RIPEMD128_DIGEST_LENGTH) return -1;
    RIPEMD128_CTX ctx_rmd;
    ripemd128_init(&ctx_rmd);
    ripemd128_update(&ctx_rmd, msg, msg_len);
    if (nonce && nonce_len > 0) ripemd128_update(&ctx_rmd, nonce, nonce_len);
    ripemd128_final(out_hash, &ctx_rmd);
    return 0;
}

int pow_hash_ripemd256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    // RIPEMD256 digest length is 32 bytes
    if (out_len < 32) return -1;
    RIPEMD256_CTX ctx_rmd;
    ripemd256_init(&ctx_rmd);
    ripemd256_update(&ctx_rmd, msg, msg_len);
    if (nonce && nonce_len > 0) ripemd256_update(&ctx_rmd, nonce, nonce_len);
    ripemd256_final(out_hash, &ctx_rmd);
    return 0;
}

int pow_hash_ripemd320(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    // RIPEMD320 digest length is 40 bytes
    if (out_len < 40) return -1;
    RIPEMD320_CTX ctx_rmd;
    ripemd320_init(&ctx_rmd);
    ripemd320_update(&ctx_rmd, msg, msg_len);
    if (nonce && nonce_len > 0) ripemd320_update(&ctx_rmd, nonce, nonce_len);
    ripemd320_final(out_hash, &ctx_rmd);
    return 0;
}

int pow_hash_has160(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < HAS160_DIGEST_LENGTH) return -1;
    HAS160_CTX ctx_has;
    has160_init(&ctx_has);
    has160_update(&ctx_has, msg, msg_len);
    if (nonce && nonce_len > 0) has160_update(&ctx_has, nonce, nonce_len);
    has160_final(out_hash, &ctx_has);
    return 0;
}
