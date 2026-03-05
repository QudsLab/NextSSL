/**
 * @file root/pow/root_pow.c (Lite)
 * @brief NextSSL Root Lite -- Proof-of-Work implementation.
 *
 * Delegates to the PoW subsystem (core/server/client).
 * Lite build only: sha256, sha512, blake3, argon2id.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_pow.h"
#include "../../../../../PoW/server/pow_server.h"
#include "../../../../../PoW/client/pow_client.h"
#include "../../../../../PoW/core/pow_types.h"
#include "../../../../../PoW/core/pow_encode.h"
#include "../../../../../PoW/core/pow_difficulty.h"
#include "../../../../../PoW/core/pow_timer.h"
#include <string.h>

/* -------------------------------------------------------------------------
 * Server
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_server_challenge(const char *algo,
                                                   uint32_t difficulty,
                                                   char *out, size_t *out_len) {
    if (!out || !out_len) return -1;
    const char *a = algo ? algo : "sha256";
    return pow_server_create_challenge(a, difficulty, out, out_len);
}

NEXTSSL_API int nextssl_root_pow_server_verify(const char *challenge_tok,
                                                const char *solution_tok,
                                                uint32_t max_age_secs) {
    if (!challenge_tok || !solution_tok) return -1;
    return pow_server_verify_solution(challenge_tok, solution_tok, max_age_secs);
}

/* -------------------------------------------------------------------------
 * Client
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_client_parse(const char *token,
                                               char *algo_out,
                                               uint32_t *diff_out,
                                               char *nonce_out,
                                               time_t *ts_out) {
    if (!token) return -1;
    return pow_client_parse_challenge(token, algo_out, diff_out, nonce_out, ts_out);
}

NEXTSSL_API int nextssl_root_pow_client_solve(const char *challenge_tok,
                                               char *solution_out, size_t *sol_len,
                                               uint64_t max_iters) {
    if (!challenge_tok || !solution_out || !sol_len) return -1;
    return pow_client_solve(challenge_tok, solution_out, sol_len, max_iters);
}

NEXTSSL_API int nextssl_root_pow_client_limits(const char *algo,
                                                uint64_t *limit_out) {
    if (!algo || !limit_out) return -1;
    return pow_client_get_limits(algo, limit_out);
}

NEXTSSL_API int nextssl_root_pow_client_reject(const char *challenge_tok,
                                                char *reason_out, size_t reason_len) {
    if (!challenge_tok) return -1;
    return pow_client_reject(challenge_tok, reason_out, reason_len);
}

/* -------------------------------------------------------------------------
 * Encode / decode
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_encode(const uint8_t *in, size_t in_len,
                                         char *out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    return pow_encode_b64(in, in_len, out, out_len);
}

NEXTSSL_API int nextssl_root_pow_decode(const char *in,
                                         uint8_t *out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    return pow_decode_b64(in, out, out_len);
}

/* -------------------------------------------------------------------------
 * Difficulty helpers
 * ---------------------------------------------------------------------- */

NEXTSSL_API uint64_t nextssl_root_pow_difficulty_expected_iter(uint32_t difficulty) {
    return pow_difficulty_expected_iter(difficulty);
}

NEXTSSL_API double nextssl_root_pow_difficulty_estimate_ms(const char *algo,
                                                            uint32_t difficulty) {
    if (!algo) return -1.0;
    return pow_difficulty_estimate_ms(algo, difficulty);
}

NEXTSSL_API int nextssl_root_pow_difficulty_adjust(const char *algo,
                                                    double target_ms,
                                                    uint32_t current_diff,
                                                    uint32_t *result_diff) {
    if (!algo || !result_diff) return -1;
    return pow_difficulty_adjust(algo, target_ms, current_diff, result_diff);
}

/* -------------------------------------------------------------------------
 * Timer
 * ---------------------------------------------------------------------- */

NEXTSSL_API uint64_t nextssl_root_pow_timer_now_ms(void) {
    return pow_timer_now_ms();
}

NEXTSSL_API double nextssl_root_pow_timer_elapsed_ms(uint64_t start_ms) {
    return pow_timer_elapsed_ms(start_ms);
}

NEXTSSL_API int nextssl_root_pow_timer_benchmark(const char *algo,
                                                  uint32_t duration_ms,
                                                  double *hps_out) {
    if (!algo || !hps_out) return -1;
    return pow_timer_benchmark(algo, duration_ms, hps_out);
}
