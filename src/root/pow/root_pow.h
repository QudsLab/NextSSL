/* root_pow.h — exported PoW API (Plan 405)
 *
 * Header-only re-declaration of the pow_api.c exports under the unified
 * nextssl.h umbrella.  No new .c file is needed — the symbols are already
 * defined and exported by src/pow/pow_api.c.
 *
 * Include order: consumers get this via nextssl.h.
 */
#ifndef ROOT_POW_H
#define ROOT_POW_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"
#include "../../pow/core/pow_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Server API
 * -------------------------------------------------------------------------*/

/* Generate a PoW challenge.
 * algorithm_id — canonical hyphen-form, e.g. "sha3-256", "blake3"
 * Returns 0 on success. */
NEXTSSL_API int nextssl_pow_server_generate_challenge(
    const pow_config_t *config,
    const char         *algorithm_id,
    const uint8_t      *context,
    size_t              context_len,
    uint32_t            difficulty_bits,
    pow_challenge_t    *out);

/* Verify a client solution.
 * out_valid — set to 1 if valid, 0 if invalid.
 * Returns 0 on success (check out_valid), negative on error. */
NEXTSSL_API int nextssl_pow_server_verify_solution(
    const pow_challenge_t *challenge,
    const pow_solution_t  *solution,
    int                   *out_valid);

/* -------------------------------------------------------------------------
 * Client API
 * -------------------------------------------------------------------------*/

/* Parse a base64-encoded challenge string from the server. */
NEXTSSL_API int nextssl_pow_client_parse_challenge(
    const char      *challenge_b64,
    pow_challenge_t *out);

/* Solve a PoW challenge (blocking).
 * Returns 0 on success. */
NEXTSSL_API int nextssl_pow_client_solve(
    const pow_challenge_t *challenge,
    pow_solution_t        *out);

/* Check whether the challenge's resource requirements are within limits.
 * out_acceptable — set to 1 if within limits. */
NEXTSSL_API int nextssl_pow_client_check_limits(
    const pow_challenge_t *challenge,
    uint64_t               max_wu,
    uint64_t               max_mu_kb,
    double                 max_time_seconds,
    int                   *out_acceptable);

/* -------------------------------------------------------------------------
 * Codec API (shared serialisation)
 * -------------------------------------------------------------------------*/

NEXTSSL_API int nextssl_pow_challenge_encode(
    const pow_challenge_t *challenge,
    char                  *out_buf,
    size_t                 out_len);

NEXTSSL_API int nextssl_pow_solution_encode(
    const pow_solution_t  *solution,
    char                  *out_buf,
    size_t                 out_len);

NEXTSSL_API int nextssl_pow_solution_decode(
    const char     *base64_str,
    pow_solution_t *out);

NEXTSSL_API void nextssl_pow_algo_name_normalise(char *name);

/* -------------------------------------------------------------------------
 * Cost Model API — Plan 40005/40006
 *
 * Formula-driven, architecture-independent cost for any algorithm.
 * All fields in nextssl_cost_result_t are set from source-verified formulas;
 * no benchmarking is needed for formula output.
 *
 * nextssl_cost_probe() additionally runs the algorithm live (n_trials times)
 * and reports measured nanosecond timing alongside the formula values.
 *
 * Both calls require nextssl_init() to have been called first so that
 * hash_cost_registry_init() has run and the plugin table has been validated.
 * -------------------------------------------------------------------------*/

/* Thin public aliases for the internal structs.
 * Consumers include only nextssl.h / root_pow.h — they never need to
 * include hash_cost.h or hash_cost_probe.h directly. */
#include "../../pow/dhcm/hash_cost.h"
#include "../../pow/dhcm/hash_cost_probe.h"

typedef hash_cost_t               nextssl_cost_result_t;
typedef hash_cost_probe_result_t  nextssl_cost_probe_result_t;

/* Formula-only: compute the 8-dimension cost for algo_name at cost_params.
 * algo_name   — canonical name, e.g. "argon2id", "sha256".
 * cost_params — pointer to the matching hash_cost_params_*_t struct.
 * params_size — sizeof(*cost_params).
 * out         — filled with all 8 cost dimensions.
 *
 * Returns  0 on success.
 * Returns -1 if algo_name not registered.
 * Returns -2 if cost_params or out is NULL. */
NEXTSSL_API int nextssl_cost_compute(
    const char             *algo_name,
    const void             *cost_params,
    size_t                  params_size,
    nextssl_cost_result_t  *out);

/* Live benchmark + formula: runs the adapter n_trials times, measures
 * nanosecond timing, and fills formula fields via hash_cost_compute().
 *
 * For memory-hard (DF) algorithms cost_params MUST NOT be NULL — the probe
 * needs them to compute the formula side. For fast hashes cost_params may
 * be NULL (defaults to 64-byte input).
 *
 * The adapter is created internally from algo_name + cost_params, run
 * n_trials times (+ one warm-up), then destroyed. The caller never touches
 * the adapter directly.
 *
 * Returns PROBE_OK (0) on success, or one of the PROBE_ERR_* codes. */
NEXTSSL_API int nextssl_cost_probe(
    const char                  *algo_name,
    const void                  *cost_params,
    size_t                       params_size,
    uint32_t                     n_trials,
    nextssl_cost_probe_result_t *out);

/* Print a formatted summary of a nextssl_cost_probe_result_t to stdout.
 * Identical to hash_cost_probe_print() but under the public API name. */
NEXTSSL_API void nextssl_cost_probe_print(
    const nextssl_cost_probe_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* ROOT_POW_H */
