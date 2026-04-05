/* pow_solver.c — client nonce search loop */
#include "pow_solver.h"
#include "pow_timer.h"
#include "../core/pow_parser.h"
#include "../core/pow_difficulty.h"
#include "../dispatcher.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

int pow_client_parse_challenge(const char *b64, pow_challenge_t *out) {
    if (!b64 || !out) return -1;
    if (pow_challenge_decode(b64, out) != 0) return -2;
    if (out->version != 1) return -3;
    if (!pow_adapter_get(out->algorithm_id)) return -4;
    return 0;
}

int pow_client_solve(const pow_challenge_t *challenge, pow_solution_t *out) {
    if (!challenge || !out) return -1;
    if (challenge->context_len > sizeof(challenge->context)) return -5;

    const pow_adapter_t *adapter = pow_adapter_get(challenge->algorithm_id);
    if (!adapter) return -4;

    uint64_t start = pow_timer_start();
    uint8_t  input[300];
    uint8_t  hash_out[64];
    bool     found = false;

    memcpy(input, challenge->context, challenge->context_len);

    for (uint64_t nonce = 0; nonce < UINT64_MAX; nonce++) {
        char nonce_str[24];
        int  nlen = snprintf(nonce_str, sizeof(nonce_str),
                             "%llu", (unsigned long long)nonce);
        if (nlen <= 0) return -3;
        if (challenge->context_len + (size_t)nlen > sizeof(input)) return -5;

        memcpy(input + challenge->context_len, nonce_str, (size_t)nlen);

        if (adapter->hash(input, challenge->context_len + (size_t)nlen,
                          NULL, hash_out) != 0) return -3;

        if (pow_hash_meets_target(hash_out, challenge->target,
                                  challenge->target_len)) {
            found = true;
            memset(out, 0, sizeof(*out));
            memcpy(out->challenge_id, challenge->challenge_id, 16);
            out->nonce = nonce;
            memcpy(out->hash_output, hash_out, challenge->target_len);
            out->hash_output_len   = challenge->target_len;
            out->attempts          = nonce + 1;
            out->solve_time_seconds= pow_timer_elapsed(start);
            break;
        }
    }

    return found ? 0 : -2;
}
