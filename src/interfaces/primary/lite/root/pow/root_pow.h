/**
 * @file root/pow/root_pow.h (Lite)
 * @brief NextSSL Root Lite -- Proof-of-Work interface.
 *
 * Lite build supports 4 algorithms:
 *   "sha256"    -- SHA-256 based PoW
 *   "sha512"    -- SHA-512 based PoW
 *   "blake3"    -- BLAKE3 based PoW
 *   "argon2id"  -- Argon2id memory-hard PoW
 *
 * Full build adds: sha224, sha3_224, sha3_256, sha3_384, sha3_512,
 *   keccak_256, shake128, shake256, blake2b, blake2s, argon2i, argon2d,
 *   md5, sha1, ripemd160, whirlpool, nt, md2, md4, sha0, has160,
 *   ripemd128, ripemd256, ripemd320.
 *
 * Challenge format (URL-safe Base64 encoded):
 *   <version>:<algo>:<difficulty>:<nonce_b64>:<timestamp>
 *
 * Solution format (URL-safe Base64 encoded):
 *   <challenge_token>:<solution_nonce_b64>
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_POW_H
#define NEXTSSL_LITE_ROOT_POW_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "../../../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum token / buffer lengths */
#define NEXTSSL_POW_MAX_TOKEN_LEN   512
#define NEXTSSL_POW_MAX_ALGO_LEN     32
#define NEXTSSL_POW_MAX_NONCE_LEN    64
#define NEXTSSL_POW_MIN_DIFFICULTY    1
#define NEXTSSL_POW_MAX_DIFFICULTY   64

/* -------------------------------------------------------------------------
 * Server side
 * ---------------------------------------------------------------------- */

/**
 * Generate a PoW challenge token.
 *
 * @param algo        Algorithm string (e.g. "sha256"). NULL → "sha256".
 * @param difficulty  Leading-zero-bit difficulty [1..64].
 * @param out         Buffer for challenge token (at least NEXTSSL_POW_MAX_TOKEN_LEN).
 * @param out_len     Receives the token length (not including NUL).
 * @return 0 on success, <0 on error.
 */
NEXTSSL_API int nextssl_root_pow_server_challenge(const char *algo,
                                                   uint32_t difficulty,
                                                   char *out, size_t *out_len);

/**
 * Verify a submitted PoW solution against the original challenge.
 *
 * @param challenge_tok  Original challenge token.
 * @param solution_tok   Solution token returned by client.
 * @param max_age_secs   Maximum acceptable age in seconds (0 = no limit).
 * @return 1 if valid, 0 if invalid, <0 on error.
 */
NEXTSSL_API int nextssl_root_pow_server_verify(const char *challenge_tok,
                                                const char *solution_tok,
                                                uint32_t max_age_secs);

/* -------------------------------------------------------------------------
 * Client side
 * ---------------------------------------------------------------------- */

/**
 * Parse a challenge token into its fields.
 *
 * @param token       Challenge token string.
 * @param algo_out    Buffer of at least NEXTSSL_POW_MAX_ALGO_LEN bytes.
 * @param diff_out    Receives difficulty value.
 * @param nonce_out   Buffer of at least NEXTSSL_POW_MAX_NONCE_LEN bytes.
 * @param ts_out      Receives Unix timestamp.
 * @return 0 on success, <0 on parse error.
 */
NEXTSSL_API int nextssl_root_pow_client_parse(const char *token,
                                               char *algo_out,
                                               uint32_t *diff_out,
                                               char *nonce_out,
                                               time_t *ts_out);

/**
 * Solve a challenge.
 *
 * @param challenge_tok  Challenge token to solve.
 * @param solution_out   Buffer for solution token (at least NEXTSSL_POW_MAX_TOKEN_LEN).
 * @param sol_len        Receives solution length.
 * @param max_iters      Max iterations per attempt (0 = unlimited).
 * @return 0 on success, 1 if max_iters exhausted, <0 on error.
 */
NEXTSSL_API int nextssl_root_pow_client_solve(const char *challenge_tok,
                                               char *solution_out, size_t *sol_len,
                                               uint64_t max_iters);

/**
 * Query the iteration limit supported by the current PoW adapter.
 *
 * @param algo       Algorithm string.
 * @param limit_out  Receives the recommended max iterations (0 = unlimited).
 * @return 0 on success.
 */
NEXTSSL_API int nextssl_root_pow_client_limits(const char *algo,
                                                uint64_t *limit_out);

/**
 * Tell the PoW subsystem to reject a challenge without solving it.
 * Useful when difficulty is unreasonably high.
 *
 * @param challenge_tok  Challenge token.
 * @param reason_out     Buffer for human-readable reason (may be NULL).
 * @param reason_len     Buffer length.
 * @return 0 on success.
 */
NEXTSSL_API int nextssl_root_pow_client_reject(const char *challenge_tok,
                                                char *reason_out, size_t reason_len);

/* -------------------------------------------------------------------------
 * Encode / decode helpers
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_encode(const uint8_t *in, size_t in_len,
                                         char *out, size_t *out_len);

NEXTSSL_API int nextssl_root_pow_decode(const char *in,
                                         uint8_t *out, size_t *out_len);

/* -------------------------------------------------------------------------
 * Difficulty helpers
 * ---------------------------------------------------------------------- */

/**
 * Estimate expected iterations for a given difficulty.
 * Returns 2^difficulty.
 */
NEXTSSL_API uint64_t nextssl_root_pow_difficulty_expected_iter(uint32_t difficulty);

/**
 * Estimate wall-clock time in milliseconds for a difficulty
 * based on measured hash rate.
 */
NEXTSSL_API double nextssl_root_pow_difficulty_estimate_ms(const char *algo,
                                                            uint32_t difficulty);

/**
 * Adjust difficulty to target a desired solve time (milliseconds).
 *
 * @param algo          Algorithm string.
 * @param target_ms     Target solve time.
 * @param current_diff  Starting difficulty hint.
 * @param result_diff   Recommended difficulty.
 * @return 0 on success.
 */
NEXTSSL_API int nextssl_root_pow_difficulty_adjust(const char *algo,
                                                    double target_ms,
                                                    uint32_t current_diff,
                                                    uint32_t *result_diff);

/* -------------------------------------------------------------------------
 * Timer utilities
 * ---------------------------------------------------------------------- */

NEXTSSL_API uint64_t nextssl_root_pow_timer_now_ms(void);
NEXTSSL_API double   nextssl_root_pow_timer_elapsed_ms(uint64_t start_ms);

/**
 * Benchmark: returns hashes-per-second for the given algo.
 *
 * @param algo         Algorithm string.
 * @param duration_ms  Benchmark duration in ms (e.g. 1000).
 * @param hps_out      Receives hashes/second estimate.
 * @return 0 on success.
 */
NEXTSSL_API int nextssl_root_pow_timer_benchmark(const char *algo,
                                                  uint32_t duration_ms,
                                                  double *hps_out);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_POW_H */
