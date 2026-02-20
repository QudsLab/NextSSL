#include "verify.h"
#include "../core/pow_difficulty.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

extern POWAlgoAdapter* pow_adapter_get(const char* algorithm_id);

int pow_server_verify_solution(
    POWChallenge* challenge,
    POWSolution* solution,
    bool* out_valid
) {
    if (!challenge || !solution || !out_valid) return -1;
    *out_valid = false;
    
    // 1. Check challenge_id
    if (memcmp(challenge->challenge_id, solution->challenge_id, 16) != 0) return -2;
    
    // 2. Check expiry
    if ((uint64_t)time(NULL) > challenge->expires_unix) return -1;
    
    // 3. Recompute hash
    POWAlgoAdapter* adapter = pow_adapter_get(challenge->algorithm_id);
    if (!adapter) return -3;
    
    // Construct input: context || nonce
    // Assuming max context 256 + nonce string (max 20 chars for uint64)
    uint8_t input[300];
    memcpy(input, challenge->context, challenge->context_len);
    
    // Append nonce as string to match client solver
    char nonce_str[32];
    int nonce_len = sprintf(nonce_str, "%llu", (unsigned long long)solution->nonce);
    
    if (challenge->context_len + nonce_len > sizeof(input)) return -3;
    
    memcpy(input + challenge->context_len, nonce_str, nonce_len);
    
    uint8_t hash_output[64];
    if (adapter->hash(input, challenge->context_len + nonce_len, challenge->algo_params, hash_output) != 0) return -3;
    
    // 4. Compare to target
    if (pow_difficulty_check(hash_output, challenge->target, challenge->target_len)) {
        *out_valid = true;
    }
    
    return 0;
}
