/**
 * @file root/pow/root_pow.c
 * @brief NextSSL Root -- Proof-of-Work explicit interface implementation.
 *
 * Thin wrappers that forward every call to the PoW subsystem.
 * No logic lives here — all behaviour is in the subsystem.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_pow.h"

/* PoW subsystem headers */
#include "../../../PoW/core/pow_difficulty.h"
#include "../../../PoW/core/pow_parser.h"
#include "../../../PoW/server/challenge.h"
#include "../../../PoW/server/verify.h"
#include "../../../PoW/client/solver.h"
#include "../../../PoW/client/limits.h"
#include "../../../PoW/client/reject.h"
#include "../../../PoW/client/timer.h"

/* ==========================================================================
 * Server
 * ========================================================================== */

NEXTSSL_API int nextssl_root_pow_server_challenge(
    POWConfig     *config,
    const char    *algorithm_id,
    const uint8_t *context_data,
    size_t         context_len,
    uint32_t       difficulty_bits,
    POWChallenge  *out_challenge)
{
    return pow_server_generate_challenge(config, algorithm_id,
                                         context_data, context_len,
                                         difficulty_bits, out_challenge);
}

NEXTSSL_API int nextssl_root_pow_server_verify(
    POWChallenge *challenge,
    POWSolution  *solution,
    bool         *out_valid)
{
    return pow_server_verify_solution(challenge, solution, out_valid);
}

/* ==========================================================================
 * Client
 * ========================================================================== */

NEXTSSL_API int nextssl_root_pow_client_parse(
    const char   *challenge_b64,
    POWChallenge *out_challenge)
{
    return pow_client_parse_challenge(challenge_b64, out_challenge);
}

NEXTSSL_API int nextssl_root_pow_client_solve(
    POWChallenge *challenge,
    POWSolution  *out_solution)
{
    return pow_client_solve(challenge, out_solution);
}

NEXTSSL_API int nextssl_root_pow_client_limits(
    POWChallenge *challenge,
    uint64_t      max_wu,
    uint64_t      max_mu,
    double        max_time_seconds,
    bool         *out_acceptable)
{
    return pow_client_check_limits(challenge, max_wu, max_mu,
                                   max_time_seconds, out_acceptable);
}

NEXTSSL_API int nextssl_root_pow_client_reject(
    POWChallenge    *challenge,
    POWRejectReason *out_reason)
{
    return pow_client_reject_challenge(challenge, out_reason);
}

/* ==========================================================================
 * Serialisation
 * ========================================================================== */

NEXTSSL_API int nextssl_root_pow_encode_challenge(
    const POWChallenge *challenge,
    char               *out_str,
    size_t              out_len)
{
    return pow_parser_encode_challenge(challenge, out_str, out_len);
}

NEXTSSL_API int nextssl_root_pow_decode_challenge(
    const char   *b64_str,
    POWChallenge *out_challenge)
{
    return pow_parser_decode_challenge(b64_str, out_challenge);
}

NEXTSSL_API int nextssl_root_pow_encode_solution(
    const POWSolution *solution,
    char              *out_str,
    size_t             out_len)
{
    return pow_parser_encode_solution(solution, out_str, out_len);
}

NEXTSSL_API int nextssl_root_pow_decode_solution(
    const char  *b64_str,
    POWSolution *out_solution)
{
    return pow_parser_decode_solution(b64_str, out_solution);
}

/* ==========================================================================
 * Difficulty helpers
 * ========================================================================== */

NEXTSSL_API int nextssl_root_pow_bits_to_target(
    uint32_t bits,
    uint8_t *out_target,
    size_t   target_len)
{
    return pow_difficulty_bits_to_target(bits, out_target, target_len);
}

NEXTSSL_API int nextssl_root_pow_check_target(
    const uint8_t *hash,
    const uint8_t *target,
    size_t         len)
{
    return pow_difficulty_check(hash, target, len);
}

/* ==========================================================================
 * Timer
 * ========================================================================== */

NEXTSSL_API uint64_t nextssl_root_pow_timer_start(void)
{
    return pow_timer_start();
}

NEXTSSL_API double nextssl_root_pow_timer_stop(uint64_t start)
{
    return pow_timer_stop(start);
}
