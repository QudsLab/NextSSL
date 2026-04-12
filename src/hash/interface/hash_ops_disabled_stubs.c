/* hash_ops_disabled_stubs.c
 *
 * Provides stub hash_ops_t definitions for algorithms that are disabled
 * in this build (no implementation sources compiled), but whose symbols are
 * still referenced unconditionally by hash_registry.c / seed hash_registry.c.
 *
 * These stubs are safe to register but must never be invoked — they return
 * error codes / zero output from their function pointers.
 */

#include "hash_ops.h"
#include <string.h>
#include <stdint.h>

/* ── shared no-op helpers ─────────────────────────────────────── */
static void disabled_init  (void *ctx)                             { (void)ctx; }
static void disabled_update(void *ctx, const uint8_t *d, size_t l){ (void)ctx; (void)d; (void)l; }
static void disabled_final (void *ctx, uint8_t *out)               { (void)ctx; memset(out, 0, 32); }

/* ── scrypt ─────────────────────────────────────────────────────── */
#ifndef ENABLE_SCRYPT
const hash_ops_t scrypt_ops = {
    "scrypt", 32, 64,
    HASH_USAGE_SEED,
    disabled_init, disabled_update, disabled_final,
    1.0, 65536.0, 1
};
#endif

/* ── yescrypt ───────────────────────────────────────────────────── */
#ifndef ENABLE_YESCRYPT
const hash_ops_t yescrypt_ops = {
    "yescrypt", 32, 64,
    HASH_USAGE_SEED,
    disabled_init, disabled_update, disabled_final,
    1.0, 65536.0, 1
};
#endif

/* ── catena ─────────────────────────────────────────────────────── */
#ifndef ENABLE_CATENA
const hash_ops_t catena_ops = {
    "catena", 64, 64,
    HASH_USAGE_SEED,
    disabled_init, disabled_update, disabled_final,
    1.0, 32768.0, 1
};
#endif

/* ── lyra2 ──────────────────────────────────────────────────────── */
#ifndef ENABLE_LYRA2
const hash_ops_t lyra2_ops = {
    "lyra2", 32, 64,
    HASH_USAGE_SEED,
    disabled_init, disabled_update, disabled_final,
    1.0, 32768.0, 1
};
#endif

/* ── argon2 (generic alias → mirrors argon2id semantics) ─────────
 * seed/hash/hash_registry.c registers &argon2_ops as a generic
 * "argon2" label.  Provide a real stub so the linker is satisfied.
 * The actual argon2id/argon2i/argon2d ops defined in hash_registry.c
 * are the ones that should be used for real operations.
 * ─────────────────────────────────────────────────────────────────*/
const hash_ops_t argon2_ops = {
    "argon2", 32, 64,
    HASH_USAGE_SEED,
    disabled_init, disabled_update, disabled_final,
    1.0, 65536.0, 1
};

/* pomelo_ops and makwa_ops are defined in their respective _ops.c files (always compiled). */
