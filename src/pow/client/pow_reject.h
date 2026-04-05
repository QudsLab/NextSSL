/* pow_reject.h — client-side challenge rejection reasons */
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
    POW_REJECT_UNKNOWN,
} pow_reject_reason_t;

/* Inspect a challenge and report why it should be rejected (if at all).
 * Returns 0 on success; *out_reason == POW_REJECT_NONE means accept. */
int pow_client_reject_reason(
    const pow_challenge_t *challenge,
    pow_reject_reason_t   *out_reason
);

#endif /* POW_REJECT_H */
