/* pow_reject.c */
#include "pow_reject.h"
#include "../dispatcher.h"
#include <time.h>

int pow_client_reject_reason(
    const pow_challenge_t *challenge,
    pow_reject_reason_t   *out_reason
) {
    if (!challenge || !out_reason) return -1;
    *out_reason = POW_REJECT_NONE;

    if ((uint64_t)time(NULL) > challenge->expires_unix) {
        *out_reason = POW_REJECT_EXPIRED;
        return 0;
    }
    if (!pow_adapter_get(challenge->algorithm_id)) {
        *out_reason = POW_REJECT_ALGO_UNSUPPORTED;
        return 0;
    }
    return 0;
}
