#include "seed_password.h"
#include "../../primitives/hash/memory_hard/Argon2id/argon2id.h"

int seed_password_derive(const uint8_t                *pwd,    size_t pwd_len,
                         const uint8_t                *salt,   size_t salt_len,
                         const keygen_argon2_params_t *params,
                         uint8_t                      *out,    size_t out_len) {
    if (!pwd || pwd_len == 0 || !salt || salt_len < 16 || !out || out_len == 0)
        return -1;

    uint32_t t = params ? params->t_cost      : KEYGEN_ARGON2_DEFAULT_T_COST;
    uint32_t m = params ? params->m_cost_kib  : KEYGEN_ARGON2_DEFAULT_M_COST_KIB;
    uint32_t p = params ? params->parallelism : KEYGEN_ARGON2_DEFAULT_PARALLELISM;

    if (t == 0 || m == 0 || p == 0) return -1;

    int rc = argon2id_hash_raw(t, m, p,
                               pwd,  pwd_len,
                               salt, salt_len,
                               out,  out_len);
    /* argon2id_hash_raw returns ARGON2_OK (0) on success */
    return (rc == 0) ? 0 : -1;
}
