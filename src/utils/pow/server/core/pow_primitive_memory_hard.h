#ifndef LEYLINE_POW_PRIMITIVE_MEMORY_HARD_H
#define LEYLINE_POW_PRIMITIVE_MEMORY_HARD_H

#include "pow_hash_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int pow_hash_argon2id(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
