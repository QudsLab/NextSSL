#include "pow_primitive_memory_hard.h"
#include "../../../primitives/hash/memory_hard/utils/argon2.h"

int pow_hash_argon2id(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    const Argon2Ctx *a2ctx = (const Argon2Ctx *)ctx;
    const void *pwd = msg;
    size_t pwd_len = msg_len;
    const void *salt = nonce;
    size_t salt_len = nonce_len;
    uint32_t t_cost = 0;
    uint32_t m_cost_kb = 0;
    uint32_t parallelism = 0;
    char *encoded = NULL;
    size_t encoded_len = 0;

    if (a2ctx) {
        if (a2ctx->pwd) {
            pwd = a2ctx->pwd;
            pwd_len = a2ctx->pwd_len;
        }
        if (a2ctx->salt) {
            salt = a2ctx->salt;
            salt_len = a2ctx->salt_len;
        }
        t_cost = a2ctx->t_cost;
        m_cost_kb = a2ctx->m_cost_kb;
        parallelism = a2ctx->parallelism;
        if (a2ctx->encoded && a2ctx->encoded_len > 0) {
            encoded = a2ctx->encoded;
            encoded_len = a2ctx->encoded_len;
        }
    }

    if (!pwd || !salt || t_cost == 0 || m_cost_kb == 0 || parallelism == 0 || out_len == 0) return -1;
    if (salt_len < ARGON2_MIN_SALT_LENGTH) return -1;

    return argon2_hash(
        t_cost,
        m_cost_kb,
        parallelism,
        pwd, pwd_len,
        salt, salt_len,
        out_hash, out_len,
        encoded, encoded_len,
        Argon2_id,
        ARGON2_VERSION_NUMBER
    );
}
