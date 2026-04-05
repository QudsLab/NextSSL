/* pow_types.h — Core PoW data structures and adapter contract.
 *
 * All types are lowercase. POWAlgoAdapter is gone; use pow_adapter_t.
 */
#ifndef POW_TYPES_H
#define POW_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../dhcm/dhcm_types.h"

/* -------------------------------------------------------------------------
 * Challenge — issued by server, solved by client
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t  version;               /* protocol version (1) */
    uint8_t  challenge_id[16];      /* random UUID — links challenge to solution */

    char     algorithm_id[32];      /* canonical hyphen-form name e.g. "sha3-256" */
    uint8_t  context[256];          /* server-controlled context bytes */
    size_t   context_len;

    uint8_t  target[64];            /* difficulty target: hash < target */
    size_t   target_len;
    uint32_t difficulty_bits;       /* leading zero bits required */

    uint64_t wu;                    /* expected Work Units (from DHCM) */
    uint64_t mu;                    /* expected Memory Units KB (from DHCM) */

    uint64_t expires_unix;          /* expiry timestamp (Unix seconds) */
} pow_challenge_t;

/* -------------------------------------------------------------------------
 * Solution — produced by client, verified by server
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t  challenge_id[16];      /* must match challenge */
    uint64_t nonce;                 /* winning nonce */
    uint8_t  hash_output[64];       /* hash(context || nonce_str) */
    size_t   hash_output_len;

    double   solve_time_seconds;
    uint64_t attempts;
} pow_solution_t;

/* -------------------------------------------------------------------------
 * Server configuration
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t default_difficulty_bits;
    uint64_t max_wu_per_challenge;
    uint64_t challenge_ttl_seconds;
    char    *allowed_algos[64];
    size_t   allowed_algos_count;
    uint32_t max_challenges_per_ip;
    uint32_t rate_limit_window_seconds;
} pow_config_t;

/* -------------------------------------------------------------------------
 * Adapter — one per algorithm, registered in dispatcher.c
 *
 * hash():     calls hash_lookup(name) from src/hash registry, runs init/update/final.
 *             params is NULL for simple hashes; may point to algo-specific config.
 *             Returns 0 on success.
 *
 * get_cost(): builds DHCMParams for this algo and calls dhcm_core_calculate().
 *             difficulty_bits drives expected_trials for target-based algos.
 *             Returns 0 on success; fills *result.
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *name;   /* canonical hyphen-form — must match hash registry */

    int (*hash)(const uint8_t *input, size_t len,
                const void    *params,
                uint8_t       *out);

    int (*get_cost)(uint32_t    difficulty_bits,
                    DHCMResult *result);
} pow_adapter_t;

#endif /* POW_TYPES_H */
