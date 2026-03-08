#ifndef NEXTSSL_SEED_PASSWORD_H
#define NEXTSSL_SEED_PASSWORD_H

#include <stddef.h>
#include <stdint.h>

/*
 * seed_password.h — Argon2id password-based key derivation
 *                   (NIST SP 800-132 compatible)
 *
 * Primary use: deriving keys from low-entropy user passwords.
 * Argon2id provides both GPU resistance (Argon2d) and side-channel
 * resistance (Argon2i) in a single pass.
 *
 * Minimum salt_len: 16 bytes (required by Argon2 spec).
 * params == NULL uses the safe defaults below.
 *
 * Default parameters (NULL):
 *   t_cost       = 3      (3 passes)
 *   m_cost_kib   = 65536  (64 MiB)
 *   parallelism  = 4      (4 lanes)
 *
 * Return: 0 on success, -1 on invalid arguments or Argon2 internal error.
 */

typedef struct {
    uint32_t t_cost;        /* time cost  (iterations)    */
    uint32_t m_cost_kib;    /* memory cost in KiB         */
    uint32_t parallelism;   /* parallel lanes / threads   */
} keygen_argon2_params_t;

#define KEYGEN_ARGON2_DEFAULT_T_COST      3
#define KEYGEN_ARGON2_DEFAULT_M_COST_KIB  65536
#define KEYGEN_ARGON2_DEFAULT_PARALLELISM 4

int seed_password_derive(const uint8_t                *pwd,    size_t pwd_len,
                         const uint8_t                *salt,   size_t salt_len,
                         const keygen_argon2_params_t *params,
                         uint8_t                      *out,    size_t out_len);

#endif /* NEXTSSL_SEED_PASSWORD_H */
