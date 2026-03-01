#include "../../../PoW/client/solver.h"
#include "../../../PoW/client/limits.h"
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#ifndef POW_NO_GENERIC_API
EXPORT int nextssl_pow_client_solve(
    POWChallenge* challenge,
    POWSolution* out_solution
) {
    return pow_client_solve(challenge, out_solution);
}

EXPORT int nextssl_pow_client_check_limits(
    POWChallenge* challenge,
    uint64_t max_wu,
    uint64_t max_mu,
    double max_time_seconds,
    bool* out_acceptable
) {
    return pow_client_check_limits(challenge, max_wu, max_mu, max_time_seconds, out_acceptable);
}

EXPORT int nextssl_pow_client_parse_challenge(
    const char* challenge_base64,
    POWChallenge* out_challenge
) {
    return pow_client_parse_challenge(challenge_base64, out_challenge);
}
#endif

EXPORT int nextssl_pow_client_solve_sha3_256(
    POWChallenge* challenge,
    POWSolution* solution
) {
    // Check if challenge algo is sha3_256
    if (strcmp(challenge->algorithm_id, "sha3_256") != 0) return -1;
    return pow_client_solve(challenge, solution);
}
