/* pow_challenge.c — server-side challenge generation */
#include "pow_challenge.h"
#include "../core/pow_difficulty.h"
#include "../dhcm/dhcm_core.h"
#include "../pow_engine.h"
#include "../../../src/seed/rng/rng.h"
#include <string.h>
#include <time.h>

int pow_server_generate_challenge(
    const pow_server_config_t *config,
    const char                *algorithm_id,
    const uint8_t             *context,
    size_t                     context_len,
    uint32_t                   difficulty_bits,
    pow_challenge_t           *out
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

    /* Validate algorithm is registered in the engine */
    if (!pow_engine_algo_valid(algorithm_id)) return -3;

    /* Fill challenge struct */
    memset(out, 0, sizeof(*out));
    out->version = 1;

    /* Random challenge_id */
    rng_fill(out->challenge_id, sizeof(out->challenge_id));

    /* Algorithm name */
    strncpy(out->algorithm_id, algorithm_id, sizeof(out->algorithm_id) - 1);

    /* Engine config — algo points into struct, kdf is zero (use defaults) */
    out->pow_cfg.algo = out->algorithm_id;

    /* Context */
    if (context && context_len > 0) {
        if (context_len > sizeof(out->context))
            context_len = sizeof(out->context);
        memcpy(out->context, context, context_len);
        out->context_len = context_len;
    }

    /* Difficulty */
    out->difficulty_bits = difficulty_bits;

    /* Target length from engine digest size */
    size_t tlen = pow_engine_digest_size(&out->pow_cfg);
    if (tlen == 0) return -1;
    if (tlen > sizeof(out->target)) tlen = 32;
    out->target_len = tlen;
    pow_difficulty_bits_to_target(difficulty_bits, out->target, tlen);

    /* DHCM WU / MU — skip silently for algos without DHCM entries (balloon etc.) */
    DHCMResult cost;
    if (dhcm_cost_for_name(algorithm_id, difficulty_bits,
                           out->context_len ? out->context_len : 64,
                           &cost) == 0) {
        /* WU guard */
        if (config->max_wu_per_challenge > 0 &&
            cost.total_work_units > config->max_wu_per_challenge) return -2;
        out->wu = cost.total_work_units;
        out->mu = cost.total_memory_units;
    }

    /* Expiry */
    out->expires_unix = (uint64_t)time(NULL) + config->challenge_ttl_seconds;

    return 0;
}
