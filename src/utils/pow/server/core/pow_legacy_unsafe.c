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

// Add other legacy wrappers as needed, keeping them minimal for now to satisfy build
