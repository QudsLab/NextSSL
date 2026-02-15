#include "primitive_memory_hard.h"
#include "../../primitives/hash/memory_hard/utils/argon2.h"

int leyline_argon2id(const uint8_t *pwd, size_t pwd_len, 
                     const uint8_t *salt, size_t salt_len,
                     const LeylineArgon2Params *params,
                     uint8_t *out, size_t out_len) {
    return argon2id_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                             pwd, pwd_len, salt, salt_len, out, out_len);
}

int leyline_argon2i(const uint8_t *pwd, size_t pwd_len, 
                    const uint8_t *salt, size_t salt_len,
                    const LeylineArgon2Params *params,
                    uint8_t *out, size_t out_len) {
    return argon2i_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                            pwd, pwd_len, salt, salt_len, out, out_len);
}

int leyline_argon2d(const uint8_t *pwd, size_t pwd_len, 
                    const uint8_t *salt, size_t salt_len,
                    const LeylineArgon2Params *params,
                    uint8_t *out, size_t out_len) {
    return argon2d_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                            pwd, pwd_len, salt, salt_len, out, out_len);
}
