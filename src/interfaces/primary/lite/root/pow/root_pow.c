/**
 * @file root/pow/root_pow.c (Lite)
 * @brief NextSSL Root Lite -- Proof-of-Work implementation.
 *
 * Self-contained token-based PoW using SHA-256.
 * No dependency on the full PoW subsystem headers.
 *
 * Token format:
 *   Challenge: "v1:<algo>:<difficulty>:<nonce_hex16>:<timestamp>"
 *   Solution:  "<challenge_token>:<solution_hex16>"
 *
 * Verification: SHA-256(challenge_bytes || sol_bytes) must start
 * with <difficulty> leading zero bits.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_pow.h"
#include "../../../../../primitives/hash/fast/sha256/sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static const char _hex_chars[] = "0123456789abcdef";

static void _hex_encode(const uint8_t *in, size_t in_len, char *out) {
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = _hex_chars[in[i] >> 4];
        out[i * 2 + 1] = _hex_chars[in[i] & 0xF];
    }
    out[in_len * 2] = '\0';
}

static int _hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int _hex_decode(const char *in, size_t hex_len, uint8_t *out) {
    if (hex_len & 1) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = _hex_nibble(in[i * 2]);
        int lo = _hex_nibble(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Returns 1 if the first `bits` bits of `hash` are all zero. */
static int _check_leading_zeros(const uint8_t *hash, uint32_t bits) {
    for (uint32_t i = 0; i < bits; i++) {
        if ((hash[i / 8] >> (7 - (i & 7))) & 1)
            return 0;
    }
    return 1;
}

/* Hash challenge_tok (as bytes) concatenated with sol_bytes. */
static void _compute_hash(const char *challenge_tok,
                           const uint8_t *sol_bytes, size_t sol_len,
                           uint8_t hash_out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)challenge_tok, strlen(challenge_tok));
    sha256_update(&ctx, sol_bytes, sol_len);
    sha256_final(&ctx, hash_out);
}

/* -------------------------------------------------------------------------
 * Server
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_server_challenge(const char *algo,
                                                   uint32_t difficulty,
                                                   char *out, size_t *out_len) {
    if (!out || !out_len) return -1;
    if (difficulty < 1 || difficulty > 64) return -1;
    const char *a = (algo && *algo) ? algo : "sha256";

    /* Generate 8 random nonce bytes */
    srand((unsigned)time(NULL) ^ (unsigned)(size_t)out);
    uint8_t nonce[8];
    for (int i = 0; i < 8; i++)
        nonce[i] = (uint8_t)(rand() & 0xFF);
    char nonce_hex[17];
    _hex_encode(nonce, 8, nonce_hex);

    unsigned long long ts = (unsigned long long)time(NULL);
    int n = snprintf(out, *out_len, "v1:%s:%u:%s:%llu",
                     a, (unsigned)difficulty, nonce_hex, ts);
    if (n < 0 || (size_t)n >= *out_len) return -1;
    *out_len = (size_t)n;
    return 0;
}

NEXTSSL_API int nextssl_root_pow_server_verify(const char *challenge_tok,
                                                const char *solution_tok,
                                                uint32_t max_age_secs) {
    if (!challenge_tok || !solution_tok) return -1;

    /* Parse challenge: v1:<algo>:<difficulty>:<nonce_hex>:<timestamp> */
    char algo[32];
    unsigned difficulty;
    char nonce_hex[17];
    unsigned long long ts;
    if (sscanf(challenge_tok, "v1:%31[^:]:%u:%16[^:]:%llu",
               algo, &difficulty, nonce_hex, &ts) != 4)
        return -1;
    if (difficulty < 1 || difficulty > 64) return -1;

    /* Age check */
    if (max_age_secs > 0) {
        unsigned long long now = (unsigned long long)time(NULL);
        if (now > ts + max_age_secs) return 0;
    }

    /* Solution must start with the challenge token */
    size_t ch_len = strlen(challenge_tok);
    if (strncmp(solution_tok, challenge_tok, ch_len) != 0) return 0;
    if (solution_tok[ch_len] != ':') return 0;
    const char *sol_hex = solution_tok + ch_len + 1;
    size_t sol_hex_len = strlen(sol_hex);
    if (sol_hex_len == 0 || (sol_hex_len & 1)) return 0;
    size_t sol_bytes_len = sol_hex_len / 2;
    if (sol_bytes_len > 64) return 0;

    uint8_t sol_bytes[64];
    if (_hex_decode(sol_hex, sol_hex_len, sol_bytes) != 0) return 0;

    uint8_t hash[32];
    _compute_hash(challenge_tok, sol_bytes, sol_bytes_len, hash);
    return _check_leading_zeros(hash, difficulty) ? 1 : 0;
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
    char algo[32];
    unsigned difficulty;
    char nonce_hex[17];
    unsigned long long ts;
    if (sscanf(token, "v1:%31[^:]:%u:%16[^:]:%llu",
               algo, &difficulty, nonce_hex, &ts) != 4)
        return -1;
    if (algo_out)  { strncpy(algo_out, algo, 31); algo_out[31] = '\0'; }
    if (diff_out)  *diff_out = difficulty;
    if (nonce_out) { strncpy(nonce_out, nonce_hex, 16); nonce_out[16] = '\0'; }
    if (ts_out)    *ts_out = (time_t)ts;
    return 0;
}

NEXTSSL_API int nextssl_root_pow_client_solve(const char *challenge_tok,
                                               char *solution_out, size_t *sol_len,
                                               uint64_t max_iters) {
    if (!challenge_tok || !solution_out || !sol_len) return -1;

    /* Parse difficulty */
    char algo[32];
    unsigned difficulty;
    char nonce_hex[17];
    unsigned long long ts_dummy;
    if (sscanf(challenge_tok, "v1:%31[^:]:%u:%16[^:]:%llu",
               algo, &difficulty, nonce_hex, &ts_dummy) != 4)
        return -1;
    if (difficulty < 1 || difficulty > 64) return -1;

    /* Brute-force: try 8-byte nonces in sequence */
    uint8_t sol[8];
    memset(sol, 0, 8);
    uint8_t hash[32];
    uint64_t iter = 0;

    while (max_iters == 0 || iter < max_iters) {
        _compute_hash(challenge_tok, sol, 8, hash);
        if (_check_leading_zeros(hash, difficulty)) {
            char sol_hex[17];
            _hex_encode(sol, 8, sol_hex);
            int n = snprintf(solution_out, *sol_len, "%s:%s",
                             challenge_tok, sol_hex);
            if (n < 0 || (size_t)n >= *sol_len) return -1;
            *sol_len = (size_t)n;
            return 0;
        }
        /* Increment nonce (little-endian counter) */
        for (int i = 0; i < 8; i++) {
            if (++sol[i]) break;
        }
        iter++;
    }
    return -1; /* exhausted max_iters */
}

NEXTSSL_API int nextssl_root_pow_client_limits(const char *algo,
                                                uint64_t *limit_out) {
    (void)algo;
    if (limit_out) *limit_out = 0; /* unlimited */
    return 0;
}

NEXTSSL_API int nextssl_root_pow_client_reject(const char *challenge_tok,
                                                char *reason_out,
                                                size_t reason_len) {
    (void)challenge_tok;
    if (reason_out && reason_len > 0)
        strncpy(reason_out, "rejected", reason_len - 1);
    return 0;
}

/* -------------------------------------------------------------------------
 * Encode / decode stubs
 * ---------------------------------------------------------------------- */

NEXTSSL_API int nextssl_root_pow_encode(const uint8_t *in, size_t in_len,
                                         char *out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    if (*out_len < in_len * 2 + 1) return -1;
    _hex_encode(in, in_len, out);
    *out_len = in_len * 2;
    return 0;
}

NEXTSSL_API int nextssl_root_pow_decode(const char *in,
                                         uint8_t *out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    size_t hex_len = strlen(in);
    if (*out_len < hex_len / 2) return -1;
    if (_hex_decode(in, hex_len, out) != 0) return -1;
    *out_len = hex_len / 2;
    return 0;
}

/* -------------------------------------------------------------------------
 * Difficulty helpers (approximate)
 * ---------------------------------------------------------------------- */

NEXTSSL_API uint64_t nextssl_root_pow_difficulty_expected_iter(uint32_t difficulty) {
    if (difficulty >= 64) return UINT64_MAX;
    return (uint64_t)1 << difficulty;
}

NEXTSSL_API double nextssl_root_pow_difficulty_estimate_ms(const char *algo,
                                                            uint32_t difficulty) {
    (void)algo;
    /* Rough estimate: 1M SHA-256/sec on a low-end CPU */
    return (double)((uint64_t)1 << difficulty) / 1000.0;
}

NEXTSSL_API int nextssl_root_pow_difficulty_adjust(const char *algo,
                                                    double target_ms,
                                                    uint32_t current_diff,
                                                    uint32_t *result_diff) {
    (void)algo; (void)target_ms;
    if (!result_diff) return -1;
    *result_diff = current_diff;
    return 0;
}

/* -------------------------------------------------------------------------
 * Timer stubs
 * ---------------------------------------------------------------------- */

NEXTSSL_API uint64_t nextssl_root_pow_timer_now_ms(void) {
    return (uint64_t)time(NULL) * 1000;
}

NEXTSSL_API double nextssl_root_pow_timer_elapsed_ms(uint64_t start_ms) {
    return (double)(nextssl_root_pow_timer_now_ms() - start_ms);
}

