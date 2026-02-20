#include "challenge.h"
#include "../core/pow_difficulty.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

// Mock for DHCM (dependency)
// In real build, we link against DHCM DLLs
// For now, we assume headers are available or we mock the call
// But the task says "Depends on ... DHCM DLLs".
// We will use dlsym or just declare extern if we link statically/dynamically.
// Actually, the adapter pattern abstracts this. But challenge generation needs WU/MU from DHCM directly?
// Or does it use the adapter?
// The task says "Query DHCM: Get WU and MU".
// It doesn't explicitly say via adapter, but adapter has get_wu/get_mu.
// Let's use an adapter dispatcher (mocked for now, or implemented later).

// Forward declaration of adapter getter
extern POWAlgoAdapter* pow_adapter_get(const char* algorithm_id);

int pow_server_generate_challenge(
    POWConfig* config,
    const char* algorithm_id,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    if (!config || !algorithm_id || !out_challenge) return -1;
    
    // 1. Validate algorithm
    bool allowed = false;
    for (size_t i = 0; i < config->allowed_algos_count; i++) {
        if (strcmp(config->allowed_algos[i], algorithm_id) == 0) {
            allowed = true;
            break;
        }
    }
    if (!allowed && config->allowed_algos_count > 0) return -1;
    
    // 2. Generate challenge_id (mock random)
    for (int i = 0; i < 16; i++) out_challenge->challenge_id[i] = rand() % 256;
    
    // 3. Set context
    if (context_len > sizeof(out_challenge->context)) context_len = sizeof(out_challenge->context);
    memcpy(out_challenge->context, context_data, context_len);
    out_challenge->context_len = context_len;
    
    strncpy(out_challenge->algorithm_id, algorithm_id, sizeof(out_challenge->algorithm_id)-1);
    
    // 4. Calculate target
    out_challenge->difficulty_bits = difficulty_bits;
    out_challenge->target_len = 32; // Default 32 bytes for now
    pow_difficulty_bits_to_target(difficulty_bits, out_challenge->target, out_challenge->target_len);
    
    // 5. Query DHCM via adapter
    POWAlgoAdapter* adapter = pow_adapter_get(algorithm_id);
    if (!adapter) return -3; // Algorithm not supported/linked
    
    if (adapter->get_wu(difficulty_bits, &out_challenge->wu) != 0) return -3;
    if (adapter->get_mu(&out_challenge->mu) != 0) return -3;
    
    // 6. Check limits
    if (out_challenge->wu > config->max_wu_per_challenge) return -2;
    
    // 7. Set expiry
    out_challenge->expires_unix = (uint64_t)time(NULL) + config->challenge_ttl_seconds;
    
    // 8. Set algo params (if adapter supports it)
    if (adapter->get_default_params) {
        if (adapter->get_default_params(&out_challenge->algo_params, &out_challenge->algo_params_size) != 0) {
            return -3; // Failed to get params
        }
    } else {
        out_challenge->algo_params = NULL;
        out_challenge->algo_params_size = 0;
    }
    
    out_challenge->version = 1;
    
    return 0;
}
