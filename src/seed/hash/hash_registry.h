/* hash_registry.h — Central Lookup Table for Seed Hash Algorithms (Plan 404)
 *
 * Provides name-based lookup of all 41+ hash algorithm vtables for use by
 * the seed system. Entry point for algorithm selection in seed_hash_config_t.
 *
 * Usage:
 *   const hash_ops_t *e = hash_lookup_by_name("sha256");
 *   if (!e) { ... not found ... }
 */
#ifndef SEED_HASH_REGISTRY_H
#define SEED_HASH_REGISTRY_H

#include "hash_ops.h"
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Hash category constants
 * -------------------------------------------------------------------------*/
#define HASH_CAT_BLAKE       0   /* BLAKE2b, BLAKE2s, BLAKE3 */
#define HASH_CAT_FAST        1   /* SHA-2 family, SM3 */
#define HASH_CAT_LEGACY      2   /* SHA-0/1, MD2/4/5, RIPEMD, etc. */
#define HASH_CAT_MEMORY_HARD 3   /* Argon2, scrypt, bcrypt, catena, yescrypt */
#define HASH_CAT_SPONGE      4   /* SHA-3, Keccak */
#define HASH_CAT_XOF         5   /* SHAKE-128, SHAKE-256 */
#define HASH_CAT_SKEIN       6   /* Skein-256/512/1024, Threefish */
#define HASH_CAT_KMAC        7   /* NIST SP 800-185 KMAC */

/* -------------------------------------------------------------------------
 * hash_registry_entry_t — an entry in the seed hash registry table
 * -------------------------------------------------------------------------*/
typedef struct {
    const char       *name;     /* canonical algorithm name, e.g. "sha256" */
    const hash_ops_t *ops;      /* pointer to vtable instance */
    int               category; /* HASH_CAT_* constant */
} hash_registry_entry_t;

/* -------------------------------------------------------------------------
 * HASH_REGISTRY — flat array of all registered seed algorithms
 * HASH_REGISTRY_SIZE — number of entries
 * -------------------------------------------------------------------------*/
extern const hash_registry_entry_t HASH_REGISTRY[];
extern const size_t                HASH_REGISTRY_SIZE;

/* -------------------------------------------------------------------------
 * hash_lookup_by_name — find algorithm vtable by name
 * -------------------------------------------------------------------------
 * Args:
 *   algo_name — canonical name, e.g. "sha256", "blake3", "argon2id"
 *
 * Returns:
 *   Pointer to the hash_ops_t vtable instance, or NULL if not found.
 *
 * Name matching is case-sensitive.  All names use lower-case with hyphens
 * as per the convention in src/hash/interface/hash_registry.h.
 * -------------------------------------------------------------------------*/
const hash_ops_t *hash_lookup_by_name(const char *algo_name);

#endif /* SEED_HASH_REGISTRY_H */
