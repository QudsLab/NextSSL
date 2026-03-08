/* pow_api.c — Public exported API for the PoW DLL.
 *
 * Thin EXPORT wrappers around the internal pow_server_* and pow_client_*
 * functions defined in src/PoW/server/ and src/PoW/client/.
 */
#ifdef _WIN32
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

#include "server/challenge.h"
#include "server/verify.h"
#include "client/solver.h"
#include "client/limits.h"
#include "client/reject.h"
#include "adapters/primitive_memory_hard/primitive_memory_hard.h"
#include "../primitives/hash/memory_hard/Argon2id/argon2id.h"
#include "../primitives/hash/memory_hard/Argon2i/argon2i.h"
#include "../primitives/hash/memory_hard/Argon2d/argon2d.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Server API ─────────────────────────────────────────────────────────── */

EXPORT int nextssl_pow_server_generate_challenge(
    POWConfig       *config,
    const char      *algorithm_id,
    const uint8_t   *context,
    size_t           context_len,
    uint32_t         difficulty_bits,
    POWChallenge    *out
) {
    return pow_server_generate_challenge(config, algorithm_id, context, context_len, difficulty_bits, out);
}

EXPORT int nextssl_pow_server_verify_solution(
    POWChallenge *challenge,
    POWSolution  *solution,
    bool         *out_valid
) {
    return pow_server_verify_solution(challenge, solution, out_valid);
}

/* Convenience wrappers with hardcoded algorithm IDs */
EXPORT int nextssl_pow_server_generate_challenge_sha256(
    POWConfig *config, const uint8_t *ctx, size_t ctx_len,
    uint32_t bits, POWChallenge *out
) {
    return pow_server_generate_challenge(config, "sha256", ctx, ctx_len, bits, out);
}

EXPORT int nextssl_pow_server_generate_challenge_blake3(
    POWConfig *config, const uint8_t *ctx, size_t ctx_len,
    uint32_t bits, POWChallenge *out
) {
    return pow_server_generate_challenge(config, "blake3", ctx, ctx_len, bits, out);
}

EXPORT int nextssl_pow_server_generate_challenge_argon2id(
    POWConfig *config, const uint8_t *ctx, size_t ctx_len,
    uint32_t bits, POWChallenge *out
) {
    return pow_server_generate_challenge(config, "argon2id", ctx, ctx_len, bits, out);
}

EXPORT int nextssl_pow_server_generate_challenge_sha3_256(
    POWConfig *config, const uint8_t *ctx, size_t ctx_len,
    uint32_t bits, POWChallenge *out
) {
    return pow_server_generate_challenge(config, "sha3_256", ctx, ctx_len, bits, out);
}

/* ── Client API ─────────────────────────────────────────────────────────── */

EXPORT int nextssl_pow_client_solve(
    POWChallenge *challenge,
    POWSolution  *out_solution
) {
    return pow_client_solve(challenge, out_solution);
}

EXPORT int nextssl_pow_client_check_limits(
    POWChallenge *challenge,
    uint64_t      max_wu,
    uint64_t      max_mu,
    double        max_time_seconds,
    bool         *out_acceptable
) {
    return pow_client_check_limits(challenge, max_wu, max_mu, max_time_seconds, out_acceptable);
}

EXPORT int nextssl_pow_client_parse_challenge(
    const char   *challenge_b64,
    POWChallenge *out_challenge
) {
    return pow_client_parse_challenge(challenge_b64, out_challenge);
}

EXPORT int nextssl_pow_client_solve_sha3_256(
    POWChallenge *challenge,
    POWSolution  *out_solution
) {
    return pow_client_solve(challenge, out_solution);
}

/* ── Argon2 primitive wrappers ───────────────────────────────────────────── */

EXPORT int nextssl_argon2id(const uint8_t *pwd, size_t pwd_len,
                             const uint8_t *salt, size_t salt_len,
                             const LeylineArgon2Params *params,
                             uint8_t *out, size_t out_len) {
    if (!pwd || !salt || !params || !out) return -1;
    return argon2id_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                             pwd, pwd_len, salt, salt_len, out, out_len);
}

EXPORT int nextssl_argon2i(const uint8_t *pwd, size_t pwd_len,
                            const uint8_t *salt, size_t salt_len,
                            const LeylineArgon2Params *params,
                            uint8_t *out, size_t out_len) {
    if (!pwd || !salt || !params || !out) return -1;
    return argon2i_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                            pwd, pwd_len, salt, salt_len, out, out_len);
}

EXPORT int nextssl_argon2d(const uint8_t *pwd, size_t pwd_len,
                            const uint8_t *salt, size_t salt_len,
                            const LeylineArgon2Params *params,
                            uint8_t *out, size_t out_len) {
    if (!pwd || !salt || !params || !out) return -1;
    return argon2d_hash_raw(params->t_cost, params->m_cost_kb, params->parallelism,
                            pwd, pwd_len, salt, salt_len, out, out_len);
}
