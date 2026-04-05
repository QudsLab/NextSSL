/* pow_limits.h — client-side device capability check */
#ifndef POW_LIMITS_H
#define POW_LIMITS_H

#include "../core/pow_types.h"
#include <stdbool.h>

/* Check whether the challenge is within the client's acceptable cost budget.
 * Uses the WU and MU embedded in the challenge by the server (from DHCM).
 * max_time_seconds is estimated via WU / assumed_ops_per_second.
 * Returns 0 on success; fills *out_acceptable. */
int pow_client_check_limits(
    const pow_challenge_t *challenge,
    uint64_t               max_wu,
    uint64_t               max_mu_kb,
    double                 max_time_seconds,
    bool                  *out_acceptable
);

#endif /* POW_LIMITS_H */
