#include "reject.h"
#include <time.h>

// Extern dependency to check if algo is supported
extern void* pow_adapter_get(const char* algorithm_id);

int pow_client_reject_challenge(
    POWChallenge* challenge,
    POWRejectReason* out_reason
) {
    if (!challenge || !out_reason) return -1;

    *out_reason = POW_REJECT_NONE;

    // 1. Check expiry
    time_t now = time(NULL);
    if ((uint64_t)now > challenge->expires_unix) {
        *out_reason = POW_REJECT_EXPIRED;
        return 0;
    }

    // 2. Check algorithm support
    if (pow_adapter_get(challenge->algorithm_id) == NULL) {
        *out_reason = POW_REJECT_ALGO_UNSUPPORTED;
        return 0;
    }

    // 3. Limits are usually checked separately via pow_client_check_limits
    // But we could integrate them here if we had access to the limits config.
    // For now, we assume this function checks "intrinsic" invalidity.

    return 0;
}
