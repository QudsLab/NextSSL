/* pow_api.c — Public DLL-exported wrappers for the PoW subsystem.
 *
 * All exports are prefixed "nextssl_pow_" to match the project export
 * convention.  Internal calls are direct — no dynamic loading.
 *
 * Exported functions:
 *   nextssl_pow_server_generate_challenge
 *   nextssl_pow_server_verify_solution
 *   nextssl_pow_client_parse_challenge
 *   nextssl_pow_client_solve
 *   nextssl_pow_client_check_limits
 *   nextssl_pow_challenge_encode
 *   nextssl_pow_solution_encode
 *   nextssl_pow_solution_decode
 *   nextssl_pow_algo_name_normalise
 */
#include "server/pow_challenge.h"
#include "server/pow_verify.h"
#include "client/pow_solver.h"
#include "client/pow_limits.h"
#include "core/pow_parser.h"
#include "core/pow_types.h"

#include "../../root/nextssl_export.h"
#define POW_EXPORT NEXTSSL_API

/* -------------------------------------------------------------------------
 * Server API
 * ------------------------------------------------------------------------- */

POW_EXPORT
int nextssl_pow_server_generate_challenge(
    const pow_server_config_t *config,
    const char                *algorithm_id,
    const uint8_t             *context,
    size_t                     context_len,
    uint32_t                   difficulty_bits,
    pow_challenge_t           *out)
{
    return pow_server_generate_challenge(config, algorithm_id,
                                         context, context_len,
                                         difficulty_bits, out);
}

POW_EXPORT
int nextssl_pow_server_verify_solution(
    const pow_challenge_t *challenge,
    const pow_solution_t  *solution,
    int                   *out_valid)
{
    _Bool valid = 0;
    int rc = pow_server_verify_solution(challenge, solution, &valid);
    if (out_valid) *out_valid = (int)valid;
    return rc;
}

/* -------------------------------------------------------------------------
 * Client API
 * ------------------------------------------------------------------------- */

POW_EXPORT
int nextssl_pow_client_parse_challenge(
    const char      *challenge_b64,
    pow_challenge_t *out)
{
    return pow_client_parse_challenge(challenge_b64, out);
}

POW_EXPORT
int nextssl_pow_client_solve(
    const pow_challenge_t *challenge,
    pow_solution_t        *out)
{
    return pow_client_solve(challenge, out);
}

POW_EXPORT
int nextssl_pow_client_check_limits(
    const pow_challenge_t *challenge,
    uint64_t               max_wu,
    uint64_t               max_mu_kb,
    double                 max_time_seconds,
    int                   *out_acceptable)
{
    _Bool ok = 0;
    int rc = pow_client_check_limits(challenge, max_wu, max_mu_kb,
                                      max_time_seconds, &ok);
    if (out_acceptable) *out_acceptable = (int)ok;
    return rc;
}

/* -------------------------------------------------------------------------
 * Codec API (shared client/server serialisation)
 * ------------------------------------------------------------------------- */

POW_EXPORT
int nextssl_pow_challenge_encode(
    const pow_challenge_t *challenge,
    char                  *out_buf,
    size_t                 out_len)
{
    return pow_challenge_encode(challenge, out_buf, out_len);
}

POW_EXPORT
int nextssl_pow_solution_encode(
    const pow_solution_t *solution,
    char                 *out_buf,
    size_t                out_len)
{
    return pow_solution_encode(solution, out_buf, out_len);
}

POW_EXPORT
int nextssl_pow_solution_decode(
    const char     *base64_str,
    pow_solution_t *out)
{
    return pow_solution_decode(base64_str, out);
}

POW_EXPORT
void nextssl_pow_algo_name_normalise(char *name)
{
    pow_algo_name_normalise(name);
}
