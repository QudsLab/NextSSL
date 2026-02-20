#ifndef POW_LIMITS_H
#define POW_LIMITS_H

#include "../core/pow_types.h"
#include <stdbool.h>

/**
 * Check if the challenge is within acceptable cost limits.
 * 
 * @param challenge The challenge to check.
 * @param max_wu Maximum Work Units allowed.
 * @param max_mu Maximum Memory Units allowed.
 * @param max_time_seconds Maximum estimated time allowed.
 * @param out_acceptable Pointer to boolean to store the result.
 * @return 0 on success, non-zero on error.
 */
int pow_client_check_limits(
    POWChallenge* challenge,
    uint64_t max_wu,
    uint64_t max_mu,
    double max_time_seconds,
    bool* out_acceptable
);

#endif // POW_LIMITS_H
