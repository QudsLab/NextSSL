#ifndef nextssl_POW_LEGACY_UNSAFE_H
#define nextssl_POW_LEGACY_UNSAFE_H

#include "pow_hash_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int pow_hash_md2(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_md4(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_sha0(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_ripemd128(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_ripemd256(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_ripemd320(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_has160(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
