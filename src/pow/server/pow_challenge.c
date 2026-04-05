/* pow_challenge.c — server-side challenge generation */
#include "pow_challenge.h"
#include "../core/pow_difficulty.h"
#include "../dhcm/dhcm_core.h"
#include "../dispatcher.h"
#include "../../../src/seed/rng/rng.h"
#include "../../hash/interface/hash_registry.h"
#include <string.h>
#include <time.h>

int pow_server_generate_challenge(
    const pow_config_t *config,
    const char         *algorithm_id,
    const uint8_t      *context,
    size_t              context_len,
    uint32_t            difficulty_bits,
    pow_challenge_t    *out
) {
    if (!config || !algorithm_id || !out) return -1;

    /* Validate algorithm is in the allowed list (if list is set) */
    if (config->allowed_algos_count > 0) {
        int allowed = 0;
        for (size_t i = 0; i < config->allowed_algos_count; i++) {
            if (config->allowed_algos[i] &&
                strcmp(config->allowed_algos[i], algorithm_id) == 0) {
                allowed = 1; break;
            }
        }
        if (!allowed) return -1;
    }

    /* Resolve adapter — also validates algorithm is registered */
    const pow_adapter_t *adapter = pow_adapter_get(algorithm_id);
    if (!adapter) return -3;

    /* Query DHCM cost via adapter */
    DHCMResult cost;
    if (adapter->get_cost(difficulty_bits, &cost) != 0) return -4;

    /* WU guard */
    if (cost.total_work_units > config->max_wu_per_challenge) return -2;

    /* Fill challenge */
    memset(out, 0, sizeof(*out));
    out->version = 1;

    /* Random challenge_id */
    rng_fill(out->challenge_id, sizeof(out->challenge_id));

    /* Algorithm name (canonical form from adapter) */
    strncpy(out->algorithm_id, adapter->name, sizeof(out->algorithm_id) - 1);

    /* Context */
    if (context && context_len > 0) {
        if (context_len > sizeof(out->context))
            context_len = sizeof(out->context);
        memcpy(out->context, context, context_len);
        out->context_len = context_len;
    }

    /* Difficulty target */
    out->difficulty_bits = difficulty_bits;

    /* Target length = digest size from hash registry (must be PoW-eligible) */
    const hash_ops_t *h = hash_for_pow(algorithm_id);
    if (!h) return -1;  /* algorithm not valid for PoW */
    size_t tlen = h->digest_size;
    if (tlen > sizeof(out->target)) tlen = 32;
    out->target_len = tlen;
    pow_difficulty_bits_to_target(difficulty_bits, out->target, tlen);

    /* DHCM WU / MU */
    out->wu = cost.total_work_units;
    out->mu = cost.total_memory_units;

    /* Expiry */
    out->expires_unix = (uint64_t)time(NULL) + config->challenge_ttl_seconds;

    return 0;
}
