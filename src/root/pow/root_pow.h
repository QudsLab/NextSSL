/* root_pow.h — Exported PoW API (Plan 405)
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

#ifdef __cplusplus
}
#endif

#endif /* ROOT_POW_H */
