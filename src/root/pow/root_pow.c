/* root_pow.c — PoW + Cost Model exported API (Plans 405, 40005, 40006)
 *
 * Implements all symbols declared in root_pow.h:
 *   - nextssl_pow_server_* / nextssl_pow_client_* / nextssl_pow_*_encode/decode
 *   - nextssl_cost_compute  — formula cost (hash_cost_compute wrapper)
 *   - nextssl_cost_probe    — live benchmark + formula
 *   - nextssl_cost_probe_print
 *
 * Rule (Plan 40006 R2): all subsystem init calls are made from this file
 * (triggered by nextssl_init in nextssl_init.c). This file never calls
 * hash_cost_registry_init() directly; that is done in nextssl_init.c.
 *
 * Adapter factory (for nextssl_cost_probe):
 *   Internally creates a pre-configured hash_adapter_t from algo_name +
 *   cost_params, runs the probe, then destroys the adapter.
 *   The caller never sees the adapter.
 */
#include "root_pow.h"
#include "../../pow/pow_api.h"
#include "../../pow/dhcm/hash_cost.h"
#include "../../pow/dhcm/hash_cost_probe.h"
#include "../../hash/adapters/plain_hash_adapter.h"
#include "../../hash/adapters/kdf_adapters.h"
#include "../../hash/interface/hash_registry.h"
#include <string.h>
#include <stdint.h>

/* =========================================================================
 * Internal: adapter factory
 *
 * Creates and configures a hash_adapter_t from (algo_name, cost_params).
 * Returns NULL if the algo is not known or allocation fails.
 * Caller must free with hash_adapter_free().
 * ========================================================================= */
static hash_adapter_t *make_adapter(const char *name, const void *cp, size_t cs)
{
    if (!name) return NULL;

    /* ---- Memory-hard DFs --- each has its own adapter create + config -- */

    if (strcmp(name, "argon2id") == 0) {
        hash_adapter_t *a = argon2id_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_argon2_t)) {
            const hash_cost_params_argon2_t *p = cp;
            argon2id_adapter_config(a, p->m_kib, p->t_cost, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "argon2") == 0) {
        hash_adapter_t *a = argon2_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_argon2_t)) {
            const hash_cost_params_argon2_t *p = cp;
            argon2_adapter_config(a, p->m_kib, p->t_cost, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "argon2i") == 0) {
        hash_adapter_t *a = argon2i_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_argon2_t)) {
            const hash_cost_params_argon2_t *p = cp;
            argon2i_adapter_config(a, p->m_kib, p->t_cost, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "argon2d") == 0) {
        hash_adapter_t *a = argon2d_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_argon2_t)) {
            const hash_cost_params_argon2_t *p = cp;
            argon2d_adapter_config(a, p->m_kib, p->t_cost, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "scrypt") == 0) {
        hash_adapter_t *a = scrypt_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_scrypt_t)) {
            const hash_cost_params_scrypt_t *p = cp;
            scrypt_adapter_config(a, p->N, p->r, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "yescrypt") == 0) {
        hash_adapter_t *a = yescrypt_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_yescrypt_t)) {
            const hash_cost_params_yescrypt_t *p = cp;
            yescrypt_adapter_config(a, p->N, p->r, p->p, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "bcrypt") == 0) {
        hash_adapter_t *a = bcrypt_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_bcrypt_t)) {
            const hash_cost_params_bcrypt_t *p = cp;
            bcrypt_adapter_config(a, p->work_factor, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "catena") == 0) {
        hash_adapter_t *a = catena_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_catena_t)) {
            const hash_cost_params_catena_t *p = cp;
            catena_adapter_config(a, p->lambda, p->garlic, 32, NULL, 0);
        }
        return a;
    }
    if (strcmp(name, "lyra2") == 0) {
        hash_adapter_t *a = lyra2_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_lyra2_t)) {
            const hash_cost_params_lyra2_t *p = cp;
            (void)p;   /* lyra2_adapter_config() params TBD per adapter impl */
        }
        return a;
    }
    if (strcmp(name, "balloon") == 0) {
        hash_adapter_t *a = balloon_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_balloon_t)) {
            const hash_cost_params_balloon_t *p = cp;
            (void)p;   /* balloon_adapter_config() params TBD per adapter impl */
        }
        return a;
    }
    if (strcmp(name, "pomelo") == 0) {
        hash_adapter_t *a = pomelo_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_pomelo_t)) {
            const hash_cost_params_pomelo_t *p = cp;
            (void)p;
        }
        return a;
    }
    if (strcmp(name, "makwa") == 0) {
        hash_adapter_t *a = makwa_adapter_create();
        if (!a) return NULL;
        if (cp && cs >= sizeof(hash_cost_params_makwa_t)) {
            const hash_cost_params_makwa_t *p = cp;
            (void)p;
        }
        return a;
    }

    /* ---- All fast / streaming hashes ---------------------------------- */
    hash_registry_init();
    const hash_ops_t *ops = hash_lookup(name);
    if (!ops) return NULL;
    return plain_hash_adapter_create(ops);
}

/* =========================================================================
 * nextssl_cost_compute — formula cost wrapper
 * ========================================================================= */
int nextssl_cost_compute(
    const char            *algo_name,
    const void            *cost_params,
    size_t                 params_size,
    nextssl_cost_result_t *out)
{
    return hash_cost_compute(algo_name, cost_params, params_size, out);
}

/* =========================================================================
 * nextssl_cost_probe — live benchmark + formula
 * ========================================================================= */
int nextssl_cost_probe(
    const char                  *algo_name,
    const void                  *cost_params,
    size_t                       params_size,
    uint32_t                     n_trials,
    nextssl_cost_probe_result_t *out)
{
    if (!algo_name || !out) return PROBE_ERR_NULL;

    hash_adapter_t *a = make_adapter(algo_name, cost_params, params_size);
    if (!a) return PROBE_ERR_UNKNOWN_ALGO;

    int rc = hash_cost_probe(a, algo_name, cost_params, params_size, n_trials, out);

    hash_adapter_free(a);
    return rc;
}

/* =========================================================================
 * nextssl_cost_probe_print
 * ========================================================================= */
void nextssl_cost_probe_print(const nextssl_cost_probe_result_t *result)
{
    hash_cost_probe_print(result);
}

/* =========================================================================
 * PoW server/client API — thin forwarding layer over pow_api.c
 * (pow_api.c is the authoritative implementation; this file just re-exports
 *  under the NEXTSSL_API-decorated names declared in root_pow.h)
 * ========================================================================= */

int nextssl_pow_server_generate_challenge(
    const pow_config_t *config,
    const char         *algorithm_id,
    const uint8_t      *context,
    size_t              context_len,
    uint32_t            difficulty_bits,
    pow_challenge_t    *out)
{
    return pow_server_generate_challenge(
               config, algorithm_id, context, context_len, difficulty_bits, out);
}

int nextssl_pow_server_verify_solution(
    const pow_challenge_t *challenge,
    const pow_solution_t  *solution,
    int                   *out_valid)
{
    return pow_server_verify_solution(challenge, solution, out_valid);
}

int nextssl_pow_client_parse_challenge(
    const char      *challenge_b64,
    pow_challenge_t *out)
{
    return pow_client_parse_challenge(challenge_b64, out);
}

int nextssl_pow_client_solve(
    const pow_challenge_t *challenge,
    pow_solution_t        *out)
{
    return pow_client_solve(challenge, out);
}

int nextssl_pow_client_check_limits(
    const pow_challenge_t *challenge,
    uint64_t               max_wu,
    uint64_t               max_mu_kb,
    double                 max_time_seconds,
    int                   *out_acceptable)
{
    return pow_client_check_limits(
               challenge, max_wu, max_mu_kb, max_time_seconds, out_acceptable);
}

int nextssl_pow_challenge_encode(
    const pow_challenge_t *challenge,
    char                  *out_buf,
    size_t                 out_len)
{
    return pow_challenge_encode(challenge, out_buf, out_len);
}

int nextssl_pow_solution_encode(
    const pow_solution_t *solution,
    char                 *out_buf,
    size_t                out_len)
{
    return pow_solution_encode(solution, out_buf, out_len);
}

int nextssl_pow_solution_decode(
    const char     *base64_str,
    pow_solution_t *out)
{
    return pow_solution_decode(base64_str, out);
}

void nextssl_pow_algo_name_normalise(char *name)
{
    pow_algo_name_normalise(name);
}
