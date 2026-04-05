/* seed_types.h — Core Type Definitions for TIER 2 (TIER 2 types)
 *
 * Defines the configuration and state structures for deterministic
 * seed derivation via hash-based CTR-mode expansion.
 */
#ifndef SEED_TYPES_H
#define SEED_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration from hash interface */
typedef struct hash_ops_s hash_ops_t;

/* -------------------------------------------------------------------------
 * seed_hash_config_t — Configuration for hash-based seed derivation
 * -------------------------------------------------------------------------
 * Specifies:
 *   - engine: which hash algorithm to use (NULL = SHA-512 default)
 *   - ctx_label: domain separation label (e.g., "aes-256-cbc-account-7")
 */
typedef struct {
    const hash_ops_t *engine;       /* Hash algorithm vtable (NULL = SHA-512) */
    const char       *ctx_label;    /* Domain separation label */
} seed_hash_config_t;

#endif /* SEED_TYPES_H */
