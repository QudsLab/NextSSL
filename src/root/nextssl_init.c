/* nextssl_init.c — Master library startup (Plan 40006)
 *
 * nextssl_init() is the single authoritative entry point that brings up
 * ALL subsystems in dependency order.
 *
 * Rule (Plan 40006 R2): This is the ONLY file permitted to call subsystem
 * init functions. No other file in src/root/ calls them directly.
 *
 * Idempotency: implemented with a plain int flag (single-threaded assumption).
 * For multi-threaded use, the caller must issue nextssl_init() before starting
 * any threads, or provide an external mutex around the first call.
 */
#include "nextssl.h"
#include "hash/root_hash.h"
#include "../hash/interface/hash_registry.h"
#include "../pow/dhcm/hash_cost.h"
#include <stdatomic.h>
#include <stdint.h>

/* ── Idempotency flag ─────────────────────────────────────────────────────*/
static atomic_int s_initialised = 0;

/* ── nextssl_init ─────────────────────────────────────────────────────────
 * Subsystem init order (dependency graph):
 *   1. hash_registry_init()      — registers all 46 hash_ops_t entries,
 *                                  no deps.
 *   2. hash_cost_registry_init() — validates the cost plugin table;
 *                                  depends on HASH_PRIM_* constants only,
 *                                  not on hash_registry.
 *
 * seed, modern, pqc subsystems have no explicit init (lazy or compile-time).
 * pow subsystem uses hash_registry; covered by step 1.
 * --------------------------------------------------------------------------*/
int nextssl_init(void)
{
    int state = atomic_load_explicit(&s_initialised, memory_order_acquire);
    if (state == 2) return 0;

    state = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &s_initialised, &state, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        while (atomic_load_explicit(&s_initialised, memory_order_acquire) == 1) {
        }
        return atomic_load_explicit(&s_initialised, memory_order_acquire) == 2 ? 0 : -1;
    }

    /* 1. Hash algorithm registry */
    hash_registry_init();

    /* 2. Cost plugin table validation */
    if (hash_cost_registry_init() != 0) {
        atomic_store_explicit(&s_initialised, 0, memory_order_release);
        return -1;
    }

    atomic_store_explicit(&s_initialised, 2, memory_order_release);
    return 0;
}
