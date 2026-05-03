/* pbkdf2.c — PBKDF2-HMAC over hash_ops_t vtable (RFC 2898, Plan 202 / Plan 204)
 *
 * For each block i:
 *   U_1    = HMAC(pwd, salt ‖ BE32(i))
 *   U_j    = HMAC(pwd, U_{j-1})
 *   T_i    = U_1 ⊕ U_2 ⊕ … ⊕ U_c
 *
 * Plan 204: U_prev and U_curr wiped after each block.
 */
#include "pbkdf2.h"
#include "hmac.h"
#include "../../../hash/interface/hash_registry.h"
#include "../../../common/secure_zero.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int pbkdf2_ex(const hash_ops_t *hash,
              const uint8_t    *password, size_t pwdlen,
              const uint8_t    *salt,     size_t saltlen,
              uint32_t          iterations,
              uint8_t          *out,      size_t outlen)
{
    if (!password || pwdlen == 0 || !salt || saltlen == 0 || iterations == 0)
        return -1;
    if (!out || outlen == 0) return -1;

    if (!hash) {
        hash_registry_init();
        hash = hash_lookup("sha256");
        if (!hash) return -1;
    }
    if (!(hash->usage_flags & HASH_USAGE_PBKDF2)) return -1;

    size_t hash_len  = hash->digest_size;
    size_t produced  = 0;
    uint32_t block_i = 1;

    /* Scratch buffers: sized for max digest (64 bytes) */
    uint8_t u_prev[64];
    uint8_t u_curr[64];
    uint8_t xor_buf[64];
    /* salt + 4-byte block counter */
    uint8_t *salt_ctr = NULL;
    size_t   sc_len   = saltlen + 4;

    /* Stack-allocate salt+counter; fallback to heap if unusually large. */
    uint8_t salt_ctr_stack[1024];
    int     salt_ctr_heap = 0;
    if (sc_len <= sizeof(salt_ctr_stack)) {
        salt_ctr = salt_ctr_stack;
    } else {
        /* Dynamically allocate for very long salts */
        salt_ctr = (uint8_t *)malloc(sc_len);
        if (!salt_ctr) return -1;
        salt_ctr_heap = 1;
    }
    memcpy(salt_ctr, salt, saltlen);

    while (produced < outlen) {
        /* Append block counter as big-endian uint32 */
        salt_ctr[saltlen + 0] = (uint8_t)(block_i >> 24);
        salt_ctr[saltlen + 1] = (uint8_t)(block_i >> 16);
        salt_ctr[saltlen + 2] = (uint8_t)(block_i >>  8);
        salt_ctr[saltlen + 3] = (uint8_t)(block_i      );

        /* U_1 = HMAC(pwd, salt ‖ i) */
        if (hmac_compute(hash, password, pwdlen,
                         salt_ctr, sc_len, u_prev) != 0) goto err;
        memcpy(xor_buf, u_prev, hash_len);

        /* U_j = HMAC(pwd, U_{j-1}) for j = 2..iterations */
        for (uint32_t j = 1; j < iterations; j++) {
            if (hmac_compute(hash, password, pwdlen,
                             u_prev, hash_len, u_curr) != 0) goto err;
            for (size_t k = 0; k < hash_len; k++)
                xor_buf[k] ^= u_curr[k];
            memcpy(u_prev, u_curr, hash_len);
            secure_zero(u_curr, hash_len);
        }

        /* Copy block to output (may be truncated for the last block) */
        size_t copy = outlen - produced;
        if (copy > hash_len) copy = hash_len;
        memcpy(out + produced, xor_buf, copy);
        produced += copy;

        secure_zero(u_prev,  hash_len);
        secure_zero(xor_buf, hash_len);
        block_i++;
    }

    if (salt_ctr_heap) { secure_zero(salt_ctr, sc_len); free(salt_ctr); }
    return 0;

err:
    secure_zero(u_prev,  sizeof(u_prev));
    secure_zero(u_curr,  sizeof(u_curr));
    secure_zero(xor_buf, sizeof(xor_buf));
    if (salt_ctr_heap) { secure_zero(salt_ctr, sc_len); free(salt_ctr); }
    return -1;
}

/* =========================================================================
 * pbkdf2_ex_adapter — PBKDF2 using a hash_adapter_t as the PRF (Plan 40002)
 * ========================================================================= */
#include "../../../hash/adapters/hash_adapter.h"

int pbkdf2_ex_adapter(const hash_adapter_t *ha,
                      const uint8_t *password, size_t pwdlen,
                      const uint8_t *salt,     size_t saltlen,
                      uint32_t       iterations,
                      uint8_t       *out,       size_t outlen)
{
    if (!ha || !password || pwdlen == 0 || !salt || saltlen == 0) return -1;
    if (iterations == 0 || !out || outlen == 0) return -1;

    size_t hash_len = ha->digest_size ? ha->digest_size : 32;
    size_t produced  = 0;
    uint32_t block_i = 1;

    uint8_t u_prev[128];   /* generous: covers up to 1024-bit digest */
    uint8_t u_curr[128];
    uint8_t xor_buf[128];

    size_t sc_len = saltlen + 4;
    uint8_t salt_ctr_stack[1024];
    uint8_t *salt_ctr;
    int     salt_ctr_heap = 0;
    if (sc_len <= sizeof(salt_ctr_stack)) {
        salt_ctr = salt_ctr_stack;
    } else {
        salt_ctr = (uint8_t *)malloc(sc_len);
        if (!salt_ctr) return -1;
        salt_ctr_heap = 1;
    }
    memcpy(salt_ctr, salt, saltlen);

    while (produced < outlen) {
        salt_ctr[saltlen + 0] = (uint8_t)(block_i >> 24);
        salt_ctr[saltlen + 1] = (uint8_t)(block_i >> 16);
        salt_ctr[saltlen + 2] = (uint8_t)(block_i >>  8);
        salt_ctr[saltlen + 3] = (uint8_t)(block_i      );

        if (hmac_compute_adapter(ha, password, pwdlen,
                                 salt_ctr, sc_len, u_prev, hash_len) != 0) goto err2;
        memcpy(xor_buf, u_prev, hash_len);

        for (uint32_t j = 1; j < iterations; j++) {
            if (hmac_compute_adapter(ha, password, pwdlen,
                                     u_prev, hash_len, u_curr, hash_len) != 0) goto err2;
            for (size_t k = 0; k < hash_len; k++) xor_buf[k] ^= u_curr[k];
            memcpy(u_prev, u_curr, hash_len);
            secure_zero(u_curr, hash_len);
        }

        size_t copy = outlen - produced;
        if (copy > hash_len) copy = hash_len;
        memcpy(out + produced, xor_buf, copy);
        produced += copy;

        secure_zero(u_prev,  hash_len);
        secure_zero(xor_buf, hash_len);
        block_i++;
    }

    if (salt_ctr_heap) { secure_zero(salt_ctr, sc_len); free(salt_ctr); }
    return 0;

err2:
    secure_zero(u_prev,  sizeof(u_prev));
    secure_zero(u_curr,  sizeof(u_curr));
    secure_zero(xor_buf, sizeof(xor_buf));
    if (salt_ctr_heap) { secure_zero(salt_ctr, sc_len); free(salt_ctr); }
    return -1;
}
