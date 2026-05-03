/* kdf_adapters.h — Per-algorithm KDF hash adapter declarations (Plan 40002)
 *
 * Each KDF adapter carries its own heap-allocated config struct with
 * algorithm-specific parameters (memory cost, work factor, salt, etc.).
 *
 * Salt rules (applies to all KDF adapters):
 *   adapter->salt == NULL  →  auto-generate random salt via OS entropy
 *   adapter->salt != NULL  →  use pre-configured salt (deterministic output)
 *
 * Salt remains mandatory for safe KDF operation, but it is not mandatory for
 * callers to provide one explicitly because the adapters generate a random
 * default when omitted.
 *
 * Config must be called before hash.
 * Destroy with hash_adapter_free().
 */
#ifndef KDF_ADAPTERS_H
#define KDF_ADAPTERS_H

#include "hash_adapter.h"
#include "argon2.h"
#include "../../seed/random/entropy.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static inline int kdf_adapter_fill_auto_salt(uint8_t *salt,
                                             size_t salt_len)
{
    return entropy_getrandom(salt, salt_len);
}

static inline int kdf_adapter_buffer_append(uint8_t **buf,
                                            size_t *buf_len,
                                            size_t *buf_cap,
                                            const uint8_t *data,
                                            size_t data_len)
{
    size_t need;
    size_t new_cap;
    uint8_t *new_buf;

    if (!data || data_len == 0) return 0;
    if (*buf_len > ((size_t)-1) - data_len) return -1;

    need = *buf_len + data_len;
    if (need <= *buf_cap) {
        memcpy(*buf + *buf_len, data, data_len);
        *buf_len = need;
        return 0;
    }

    new_cap = (*buf_cap > 0) ? *buf_cap : 256;
    while (new_cap < need) {
        size_t grown = new_cap * 2;
        if (grown <= new_cap) {
            new_cap = need;
            break;
        }
        new_cap = grown;
    }

    new_buf = (uint8_t *)realloc(*buf, new_cap);
    if (!new_buf) return -1;

    memcpy(new_buf + *buf_len, data, data_len);
    *buf = new_buf;
    *buf_cap = new_cap;
    *buf_len = need;
    return 0;
}

/* ── Argon2id ──────────────────────────────────────────────────────────── */
hash_adapter_t *argon2id_adapter_create(void);
void argon2id_adapter_config(hash_adapter_t *a,
                              uint32_t memory,      /* KiB; 0 = keep default 65536 */
                              uint32_t iterations,  /* 0 = keep default 2          */
                              uint32_t parallelism, /* 0 = keep default 1          */
                              uint32_t key_length,  /* 0 = keep default 32         */
                              const uint8_t *salt, size_t salt_len); /* NULL = random */

/* ── Argon2i ───────────────────────────────────────────────────────────── */
hash_adapter_t *argon2i_adapter_create(void);
void argon2i_adapter_config(hash_adapter_t *a,
                             uint32_t memory, uint32_t iterations,
                             uint32_t parallelism, uint32_t key_length,
                             const uint8_t *salt, size_t salt_len);

/* ── Argon2d ───────────────────────────────────────────────────────────── */
hash_adapter_t *argon2d_adapter_create(void);
void argon2d_adapter_config(hash_adapter_t *a,
                             uint32_t memory, uint32_t iterations,
                             uint32_t parallelism, uint32_t key_length,
                             const uint8_t *salt, size_t salt_len);

/* ── Argon2 (generic family entry point; caller must supply type) ─────── */
hash_adapter_t *argon2_adapter_create(void);
void argon2_adapter_config(hash_adapter_t *a,
                            uint32_t memory, uint32_t iterations,
                            uint32_t parallelism, uint32_t key_length,
                            const uint8_t *salt, size_t salt_len,
                            argon2_type type);

/* ── Bcrypt ────────────────────────────────────────────────────────────── */
hash_adapter_t *bcrypt_adapter_create(void);
void bcrypt_adapter_config(hash_adapter_t *a,
                            uint32_t work_factor,         /* 0 = keep default 10 */
                            const uint8_t *salt,          /* NULL = random; non-NULL = 16 bytes */
                            size_t salt_len);

/* ── Scrypt ────────────────────────────────────────────────────────────── */
hash_adapter_t *scrypt_adapter_create(void);
void scrypt_adapter_config(hash_adapter_t *a,
                            uint64_t N,           /* 0 = keep default 16384     */
                            uint32_t r,           /* 0 = keep default 8         */
                            uint32_t p,           /* 0 = keep default 1         */
                            uint32_t key_length,  /* 0 = keep default 32        */
                            const uint8_t *salt, size_t salt_len);

/* ── Yescrypt ──────────────────────────────────────────────────────────── */
hash_adapter_t *yescrypt_adapter_create(void);
void yescrypt_adapter_config(hash_adapter_t *a,
                              uint64_t N,           /* 0 = keep default 16384   */
                              uint32_t r,           /* 0 = keep default 8       */
                              uint32_t p,           /* 0 = keep default 1       */
                              uint32_t key_length,  /* 0 = keep default 32      */
                              const uint8_t *salt, size_t salt_len);

/* ── Catena ────────────────────────────────────────────────────────────── */
hash_adapter_t *catena_adapter_create(void);
void catena_adapter_config(hash_adapter_t *a,
                            uint8_t  lambda,      /* 0 = keep default 2        */
                            uint8_t  garlic,      /* 0 = keep default 14       */
                            uint32_t key_length,  /* 0 = keep default 32       */
                            const uint8_t *salt, size_t salt_len);

/* ── Lyra2 ─────────────────────────────────────────────────────────────── */
hash_adapter_t *lyra2_adapter_create(void);
void lyra2_adapter_config(hash_adapter_t *a,
                           uint64_t t_cost,       /* 0 = keep default 1        */
                           uint32_t nrows,        /* 0 = keep default 8        */
                           uint32_t ncols,        /* 0 = keep default 256      */
                           uint32_t key_length,   /* 0 = keep default 32       */
                           const uint8_t *salt, size_t salt_len);

/* ── Balloon ──────────────────────────────────────────────────────────── */
hash_adapter_t *balloon_adapter_create(void);
void balloon_adapter_config(hash_adapter_t *a,
                             uint32_t s_cost,      /* 0 = keep default 1024     */
                             uint32_t t_cost,      /* 0 = keep default 3        */
                             uint32_t n_threads,   /* 0 = keep default 1        */
                             const uint8_t *salt, size_t salt_len); /* salt = 32 bytes */

/* ── Pomelo ───────────────────────────────────────────────────────────── */
hash_adapter_t *pomelo_adapter_create(void);
void pomelo_adapter_config(hash_adapter_t *a,
                            unsigned int t_cost,  /* 0 = keep default 1        */
                            unsigned int m_cost,  /* 0 = keep default 14       */
                            size_t key_length,    /* 0 = keep default 32       */
                            const uint8_t *salt, size_t salt_len);

/* ── Makwa ─────────────────────────────────────────────────────────────── */
hash_adapter_t *makwa_adapter_create(void);
void makwa_adapter_config(hash_adapter_t *a,
                           uint32_t work_factor,  /* 0 = keep default 4096     */
                           size_t key_length,     /* 0 = keep default 32       */
                           const uint8_t *salt, size_t salt_len);

#endif /* KDF_ADAPTERS_H */
