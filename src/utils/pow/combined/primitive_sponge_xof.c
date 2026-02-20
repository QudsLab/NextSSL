#include "../../../PoW/server/challenge.h"
#include "../../../PoW/server/verify.h"
#include "../../../PoW/client/solver.h"
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// Server Exports
EXPORT int leyline_pow_server_generate_challenge(
    POWConfig* config,
    const char* algorithm_id,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    return pow_server_generate_challenge(config, algorithm_id, context_data, context_len, difficulty_bits, out_challenge);
}

EXPORT int leyline_pow_server_verify_solution(
    POWChallenge* challenge,
    POWSolution* solution,
    bool* out_valid
) {
    return pow_server_verify_solution(challenge, solution, out_valid);
}

EXPORT int leyline_pow_server_generate_challenge_sha3_256(
    POWConfig* config,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
) {
    return pow_server_generate_challenge(config, "sha3_256", context_data, context_len, difficulty_bits, out_challenge);
}

// Client Exports
EXPORT int leyline_pow_client_solve(
    POWChallenge* challenge,
    POWSolution* solution
) {
    return pow_client_solve(challenge, solution);
}

EXPORT int leyline_pow_client_solve_sha3_256(
    POWChallenge* challenge,
    POWSolution* solution
) {
    if (strcmp(challenge->algorithm_id, "sha3_256") != 0) return -1;
    return pow_client_solve(challenge, solution);
}
