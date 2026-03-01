#include "../../../PoW/server/challenge.h"
#include "../../../PoW/server/verify.h"
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#ifndef POW_NO_GENERIC_API
// Generic API
EXPORT int nextssl_pow_server_generate_challenge(
    POWConfig* config,
    const char* algorithm_id,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    return pow_server_generate_challenge(config, algorithm_id, context_data, context_len, difficulty_bits, out_challenge);
}

EXPORT int nextssl_pow_server_verify_solution(
    POWChallenge* challenge,
    POWSolution* solution,
    bool* out_valid
) {
    return pow_server_verify_solution(challenge, solution, out_valid);
}
#endif

// Specific convenience wrappers (optional, but good for testing specific DLL capabilities)
EXPORT int nextssl_pow_server_generate_challenge_sha256(
    POWConfig* config,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    return pow_server_generate_challenge(config, "sha256", context_data, context_len, difficulty_bits, out_challenge);
}

EXPORT int nextssl_pow_server_generate_challenge_blake3(
    POWConfig* config,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    return pow_server_generate_challenge(config, "blake3", context_data, context_len, difficulty_bits, out_challenge);
}
