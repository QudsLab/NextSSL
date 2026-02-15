#ifndef LEYLINE_POW_LEGACY_ALIVE_H
#define LEYLINE_POW_LEGACY_ALIVE_H

#include "pow_hash_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int pow_hash_md5(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);
int pow_hash_sha1(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
