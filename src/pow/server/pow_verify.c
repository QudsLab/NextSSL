/* pow_verify.c — server-side solution verification */
#include "pow_verify.h"
#include "../core/pow_difficulty.h"
#include "../dispatcher.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>

int pow_server_verify_solution(
    const pow_challenge_t *challenge,
    const pow_solution_t  *solution,
    bool                  *out_valid
) {
    if (!challenge || !solution || !out_valid) return -1;
    *out_valid = false;

    /* Challenge ID must match */
    if (memcmp(challenge->challenge_id, solution->challenge_id, 16) != 0)
        return -2;

    /* Expiry check */
    if ((uint64_t)time(NULL) > challenge->expires_unix) return -4;

    /* Get adapter */
    const pow_adapter_t *adapter = pow_adapter_get(challenge->algorithm_id);
    if (!adapter) return -3;

    /* Reconstruct input: context || decimal_nonce_string */
    if (challenge->context_len > sizeof(challenge->context)) return -3;

    uint8_t input[300];
    memcpy(input, challenge->context, challenge->context_len);

    char nonce_str[24];
    int  nonce_len = snprintf(nonce_str, sizeof(nonce_str),
                              "%llu", (unsigned long long)solution->nonce);
    if (nonce_len <= 0 ||
        challenge->context_len + (size_t)nonce_len > sizeof(input)) return -3;

    memcpy(input + challenge->context_len, nonce_str, (size_t)nonce_len);

    uint8_t hash_out[64];
    if (adapter->hash(input, challenge->context_len + (size_t)nonce_len,
                      NULL, hash_out) != 0) return -3;

    if (pow_hash_meets_target(hash_out, challenge->target, challenge->target_len))
        *out_valid = true;

    return 0;
}
