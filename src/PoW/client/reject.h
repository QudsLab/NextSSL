#ifndef POW_REJECT_H
#define POW_REJECT_H

#include "../core/pow_types.h"

typedef enum {
    POW_REJECT_NONE = 0,
    POW_REJECT_ALGO_UNSUPPORTED,
    POW_REJECT_TOO_HARD_WU,
    POW_REJECT_TOO_HARD_MU,
    POW_REJECT_TOO_HARD_TIME,
    POW_REJECT_EXPIRED,
    POW_REJECT_INVALID_FORMAT,
    POW_REJECT_UNKNOWN
} POWRejectReason;

/**
 * Check if a challenge should be rejected and why.
 * 
 * @param challenge The challenge to evaluate.
 * @param out_reason Pointer to store the rejection reason.
 * @return 0 if check completed (even if rejected), non-zero on internal error.
 */
int pow_client_reject_challenge(
    POWChallenge* challenge,
    POWRejectReason* out_reason
);

#endif // POW_REJECT_H
