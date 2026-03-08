/**
 * @file root/pow/root_pow.h
 * @brief NextSSL Root -- Explicit Proof-of-Work interface.
 *
 * Exposes the full PoW subsystem (server challenge/verify, client
 * parse/solve/limits/reject, encoder/decoder, difficulty helpers,
 * and timer) under the nextssl_root_pow_* prefix.
 *
 * Re-exports all PoW types (POWChallenge, POWSolution, POWConfig,
 * POWAlgoAdapter, POWRejectReason) directly from the subsystem headers.
 *
 * Supported algorithm_id strings (28 total):
 *
 *   Primitive Fast (6):
 *     "sha224"     "sha256"     "sha512"
 *     "blake2b"    "blake2s"    "blake3"
 *
 *   Primitive Sponge/XOF (7):
 *     "sha3_224"   "sha3_256"   "sha3_384"   "sha3_512"
 *     "keccak_256" "shake128"   "shake256"
 *
 *   Primitive Memory-Hard (3):
 *     "argon2id"   "argon2i"    "argon2d"
 *
 *   Legacy Alive (5):
 *     "sha1"       "md5"        "ripemd160"
 *     "whirlpool"  "nt"
 *
 *   Legacy Unsafe (7):
 *     "sha0"       "md2"        "md4"
 *     "has160"     "ripemd128"  "ripemd256"  "ripemd320"
 *
 * Naming:
 *   nextssl_root_pow_server_*   -- server-side operations
 *   nextssl_root_pow_client_*   -- client-side operations
 *   nextssl_root_pow_encode_*   -- serialise challenge / solution
 *   nextssl_root_pow_decode_*   -- deserialise challenge / solution
 *   nextssl_root_pow_*          -- core helpers (difficulty, timer)
 */

#ifndef NEXTSSL_ROOT_POW_H
#define NEXTSSL_ROOT_POW_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../../../config.h"  /* NEXTSSL_API */

/* ---- Re-export PoW subsystem types ------------------------------------ */
#include "../../../PoW/core/pow_types.h"
#include "../../../PoW/client/reject.h"   /* POWRejectReason */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Server
 * ========================================================================== */

/**
 * Generate a PoW challenge.
 *
 * @param config          Server configuration (allowed algos, TTL, etc.)
 * @param algorithm_id    Algorithm name string, e.g. "argon2id", "sha256"
 * @param context_data    Opaque context bytes (IP, session token, etc.)
 * @param context_len     Length of context_data (max 256)
 * @param difficulty_bits Number of required leading zero bits
 * @param out_challenge   Pointer to POWChallenge to fill
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_server_challenge(
    POWConfig        *config,
    const char       *algorithm_id,
    const uint8_t    *context_data,
    size_t            context_len,
    uint32_t          difficulty_bits,
    POWChallenge     *out_challenge
);

/**
 * Verify a client solution against the original challenge.
 *
 * @param challenge   The original POWChallenge
 * @param solution    The POWSolution provided by the client
 * @param out_valid   Set to true if the solution is valid
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_server_verify(
    POWChallenge  *challenge,
    POWSolution   *solution,
    bool          *out_valid
);

/* ==========================================================================
 * Client
 * ========================================================================== */

/**
 * Parse a Base64-encoded challenge into a POWChallenge struct.
 *
 * @param challenge_b64  Null-terminated Base64 string from the server
 * @param out_challenge  Pointer to POWChallenge to fill
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_client_parse(
    const char    *challenge_b64,
    POWChallenge  *out_challenge
);

/**
 * Solve a PoW challenge (brute-force nonce search).
 *
 * @param challenge     The decoded POWChallenge
 * @param out_solution  Pointer to POWSolution to fill
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_client_solve(
    POWChallenge  *challenge,
    POWSolution   *out_solution
);

/**
 * Check whether a challenge is within acceptable cost limits before solving.
 *
 * @param challenge          The challenge to evaluate
 * @param max_wu             Maximum Work Units allowed
 * @param max_mu             Maximum Memory Units allowed
 * @param max_time_seconds   Maximum estimated wall time allowed
 * @param out_acceptable     Set to true if within limits
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_client_limits(
    POWChallenge  *challenge,
    uint64_t       max_wu,
    uint64_t       max_mu,
    double         max_time_seconds,
    bool          *out_acceptable
);

/**
 * Determine whether and why a challenge should be rejected.
 *
 * @param challenge    The challenge to evaluate
 * @param out_reason   Filled with the POWRejectReason (POW_REJECT_NONE = ok)
 * @return 0 on success, <0 on internal error
 */
NEXTSSL_API int nextssl_root_pow_client_reject(
    POWChallenge    *challenge,
    POWRejectReason *out_reason
);

/* ==========================================================================
 * Serialisation
 * ========================================================================== */

/** Encode a POWChallenge to a Base64 string. */
NEXTSSL_API int nextssl_root_pow_encode_challenge(
    const POWChallenge *challenge,
    char               *out_str,
    size_t              out_len
);

/** Decode a Base64 string into a POWChallenge. */
NEXTSSL_API int nextssl_root_pow_decode_challenge(
    const char   *b64_str,
    POWChallenge *out_challenge
);

/** Encode a POWSolution to a Base64 string. */
NEXTSSL_API int nextssl_root_pow_encode_solution(
    const POWSolution *solution,
    char              *out_str,
    size_t             out_len
);

/** Decode a Base64 string into a POWSolution. */
NEXTSSL_API int nextssl_root_pow_decode_solution(
    const char  *b64_str,
    POWSolution *out_solution
);

/* ==========================================================================
 * Difficulty helpers
 * ========================================================================== */

/**
 * Convert a difficulty bit-count to a binary target (H < target to pass).
 *
 * @param bits        Number of leading zero bits required
 * @param out_target  Buffer to fill (typically 32 bytes)
 * @param target_len  Length of out_target
 * @return 0 on success, <0 on error
 */
NEXTSSL_API int nextssl_root_pow_bits_to_target(
    uint32_t  bits,
    uint8_t  *out_target,
    size_t    target_len
);

/**
 * Check whether a hash value meets a difficulty target.
 *
 * @param hash    Hash bytes
 * @param target  Target bytes
 * @param len     Length of both (must match)
 * @return 1 if valid (hash < target), 0 if not
 */
NEXTSSL_API int nextssl_root_pow_check_target(
    const uint8_t *hash,
    const uint8_t *target,
    size_t         len
);

/* ==========================================================================
 * Timer
 * ========================================================================== */

/** Start a high-precision timer. Returns an opaque timestamp. */
NEXTSSL_API uint64_t nextssl_root_pow_timer_start(void);

/**
 * Stop the timer and return elapsed seconds.
 *
 * @param start  Timestamp returned by nextssl_root_pow_timer_start()
 * @return Elapsed time in seconds (double precision)
 */
NEXTSSL_API double nextssl_root_pow_timer_stop(uint64_t start);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_POW_H */
