/* nextssl_hash.h — Way 1: Generic single-entry-point hash function (Plan 40002)
 *
 * Provides a single function that dispatches to the runtime registry hash/KDF
 * hash algorithms by name at runtime, with optional configuration.
 *
 * For KDF algorithms the caller may pass a nextssl_hash_config_t to override
 * salt and work factors. If salt is omitted, a random salt is generated.
 * For plain hash algorithms (SHA-256, Blake3, etc.) config may be NULL.
 * This surface is distinct from the direct typed root API declared in
 * hash_root.h.
 */
#ifndef NEXTSSL_HASH_H
#define NEXTSSL_HASH_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * nextssl_hash_config_t — optional per-call configuration
 *
 * Fields that are irrelevant to the selected algorithm are ignored.
 * All KDF-specific integer fields default to the adapter's built-in
 * defaults when they are zero.
 * -------------------------------------------------------------------------*/
typedef struct {
    /* ---- Argon2id / Argon2i / Argon2d ---- */
    uint32_t memory;        /* KiB; 0 = default 65536                      */
    uint32_t iterations;    /* time cost; 0 = default 2                    */
    uint32_t parallelism;   /* threads;   0 = default 1                    */

    /* ---- Scrypt / Yescrypt ---- */
    uint64_t N;             /* CPU/mem cost factor; 0 = default 16384      */
    uint32_t r;             /* block size factor;   0 = default 8          */
    uint32_t p;             /* parallelism;         0 = default 1          */

    /* ---- Catena ---- */
    uint8_t  lambda;        /* bandwidth hardness;  0 = default 2          */
    uint8_t  garlic;        /* memory hardness;     0 = default 14         */

    /* ---- Lyra2 ---- */
    uint64_t t_cost;        /* time cost;   0 = default 1                  */
    uint32_t nrows;         /* rows;        0 = default 8                  */
    uint32_t ncols;         /* columns;     0 = default 256                */

    /* ---- Balloon ---- */
    uint32_t s_cost;        /* space cost;  0 = default 1024               */
    uint32_t n_threads;     /* threads;     0 = default 1                  */

    /* ---- Pomelo ---- */
    unsigned int t_cost_u;  /* t_cost (uint); 0 = default 1                */
    unsigned int m_cost_u;  /* m_cost (uint); 0 = default 14               */

    /* ---- Bcrypt / Makwa ---- */
    uint32_t work_factor;   /* bcrypt: 0=default 10; makwa: 0=default 4096 */

    /* ---- Common KDF fields ---- */
    uint32_t       key_length; /* output key length; 0 = default 32        */
    const uint8_t *salt;       /* NULL = random via entropy_getrandom()    */
    size_t         salt_len;   /* byte length of salt                      */
} nextssl_hash_config_t;

/* -------------------------------------------------------------------------
 * nextssl_hash — one-shot hash / KDF dispatch
 *
 * algo_name  — lower-case algorithm name: "sha256", "argon2id", "argon2i", "argon2d", "bcrypt", …
 * data       — input bytes (password for KDFs)
 * data_len   — input length
 * out        — caller-allocated output buffer
 * out_len    — desired output length in bytes
 * config     — pointer to nextssl_hash_config_t, or NULL to use defaults
 *              (optional for KDF algorithms; omitted salt defaults to random)
 *
 * Returns  0 on success.
 * Returns -1 if algo_name is not found.
 * Returns -2 if the internal adapter or KDF call fails.
 * -------------------------------------------------------------------------*/
int nextssl_hash(const char    *algo_name,
                 const uint8_t *data,     size_t data_len,
                 uint8_t       *out,      size_t out_len,
                 const nextssl_hash_config_t *config);

#endif /* NEXTSSL_HASH_H */
