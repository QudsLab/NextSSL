#ifndef LEYLINE_POW_HASH_TYPES_H
#define LEYLINE_POW_HASH_TYPES_H

#include "pow_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*PoW_HashFunc)(
    const uint8_t *msg, size_t msg_len,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t *out_hash, size_t out_len,
    void *ctx
);

typedef struct {
    const void *pwd;
    size_t pwd_len;
    const void *salt;
    size_t salt_len;
    uint32_t t_cost;
    uint32_t m_cost_kb;
    uint32_t parallelism;
    char *encoded;
    size_t encoded_len;
} Argon2Ctx;

typedef struct {
    const uint8_t *msg;
    size_t msg_len;
    const uint8_t *nonce;
    size_t nonce_len;
    uint8_t *out_hash;
    size_t out_len;
    const uint8_t *pwd;
    size_t pwd_len;
    const uint8_t *salt;
    size_t salt_len;
    const uint8_t *secret;
    size_t secret_len;
    const uint8_t *ad;
    size_t ad_len;
    uint32_t t_cost;
    uint32_t m_cost_kb;
    uint32_t parallelism;
    char *encoded;
    size_t encoded_len;
} PoWHashArgs;

#ifdef __cplusplus
}
#endif

#endif
