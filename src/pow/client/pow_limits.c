/* pow_limits.c */
#include "pow_limits.h"

/* Assumed baseline: 1 billion WU/second on a modern device.
 * This is intentionally conservative — the device checks its own budget. */
#define POW_ASSUMED_OPS_PER_SEC 1000000000.0

int pow_client_check_limits(
    const pow_challenge_t *challenge,
    uint64_t               max_wu,
    uint64_t               max_mu_kb,
    double                 max_time_seconds,
    bool                  *out_acceptable
) {
    if (!challenge || !out_acceptable) return -1;

    if (challenge->wu > max_wu) { *out_acceptable = false; return 0; }
    if (challenge->mu > max_mu_kb) { *out_acceptable = false; return 0; }

    double estimated = (double)challenge->wu / POW_ASSUMED_OPS_PER_SEC;
    if (estimated > max_time_seconds) { *out_acceptable = false; return 0; }

    *out_acceptable = true;
    return 0;
}
