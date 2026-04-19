/* ops_salt.h — Caller-configurable salt for KDF hash_ops_t adapters (Plan 40003)
 *
 * The argon2id, argon2i, argon2d, pomelo, and makwa accumulator ops store all input via update()
 * and run the KDF at final().  By default they use a fixed domain-separator
 * salt, which is correct for the seed system (deterministic, non-secret).
 *
 * For KAT testing or explicit salt control, call the appropriate
 * *_ops_set_salt() function ONCE on the context buffer BEFORE the first
 * init()/update()/final() cycle.  The salt persists across multiple cycles
 * on the same context (i.e. it is NOT cleared by init()).
 *
 * To revert to the domain-separator default, pass salt=NULL or salt_len=0.
 *
 * Example:
 *
 *   uint8_t ctx[HASH_OPS_CTX_MAX];
 *   uint8_t my_salt[16] = { ... };
 *
 *   argon2_ops_set_salt(ctx, my_salt, 16);   // override salt
 *   argon2id_ops.init(ctx);
 *   argon2id_ops.update(ctx, data, data_len);
 *   argon2id_ops.final(ctx, out);            // uses my_salt
 *
 *   argon2_ops_set_salt(ctx, NULL, 0);       // back to domain separator
 */
#ifndef OPS_SALT_H
#define OPS_SALT_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * argon2_ops_set_salt — applies to argon2id_ops, argon2i_ops, and argon2d_ops
 * (all share the same context layout).
 * Defined in src/hash/interface/hash_registry.c
 * -------------------------------------------------------------------------*/
void argon2_ops_set_salt(void *ctx, const uint8_t *salt, size_t salt_len);

/* -------------------------------------------------------------------------
 * pomelo_ops_set_salt — applies to pomelo_ops.
 * Defined in src/hash/memory_hard/pomelo/pomelo_ops.c
 * -------------------------------------------------------------------------*/
void pomelo_ops_set_salt(void *ctx, const uint8_t *salt, size_t salt_len);

/* -------------------------------------------------------------------------
 * makwa_ops_set_salt — applies to makwa_ops.
 * Defined in src/hash/memory_hard/makwa/makwa_ops.c
 * -------------------------------------------------------------------------*/
void makwa_ops_set_salt(void *ctx, const uint8_t *salt, size_t salt_len);

#endif /* OPS_SALT_H */
