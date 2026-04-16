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

#if !defined(ENABLE_SCRYPT) || !defined(ENABLE_YESCRYPT) || !defined(ENABLE_CATENA) || !defined(ENABLE_LYRA2)
/* ── shared no-op helpers ─────────────────────────────────────── */
static void disabled_init  (void *ctx)                             { (void)ctx; }
static void disabled_update(void *ctx, const uint8_t *d, size_t l){ (void)ctx; (void)d; (void)l; }
static void disabled_final (void *ctx, uint8_t *out)               { (void)ctx; memset(out, 0, 32); }
#endif

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

/* argon2_ops is provided by hash_registry.c as the compatibility/default
 * Argon2 entry point backed by the generic argon2.h API. */

/* pomelo_ops and makwa_ops are defined in their respective _ops.c files (always compiled). */
