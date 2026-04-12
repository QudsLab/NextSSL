/* pow_engine.c — Dynamic PoW engine.
 *
 * Delegates all hashing to the pre-built adapters in src/hash/adapters/.
 * Three sections:
 *   Part A — thin config shims (translate pow_kdf_params_t → adapter_config calls)
 *   Part B — dispatch table (name → create_fn + config_fn)
 *   Part C — three public functions
 */
#include "pow_engine.h"
#include "pow_config.h"
#include "../hash/adapters/hash_adapter.h"
#include "../hash/adapters/plain_hash_adapter.h"
#include "../hash/adapters/kdf_adapters.h"
#include <string.h>
#include <stddef.h>

/* =========================================================================
 * Part A — Config shims
 * Translate pow_kdf_params_t fields into the typed *_adapter_config() calls.
 * Zero fields → adapter uses its own built-in defaults.
 * ========================================================================= */

static void config_argon2id(hash_adapter_t *a, const pow_kdf_params_t *k) {
    argon2id_adapter_config(a, k->m_kib, k->t, k->p, 32, k->salt, k->salt_len);
}
static void config_argon2i(hash_adapter_t *a, const pow_kdf_params_t *k) {
    argon2i_adapter_config(a, k->m_kib, k->t, k->p, 32, k->salt, k->salt_len);
}
static void config_argon2d(hash_adapter_t *a, const pow_kdf_params_t *k) {
    argon2d_adapter_config(a, k->m_kib, k->t, k->p, 32, k->salt, k->salt_len);
}
static void config_argon2(hash_adapter_t *a, const pow_kdf_params_t *k) {
    argon2_adapter_config(a, k->m_kib, k->t, k->p, 32, k->salt, k->salt_len);
}
static void config_scrypt(hash_adapter_t *a, const pow_kdf_params_t *k) {
    scrypt_adapter_config(a, k->scrypt_N, k->scrypt_r, k->scrypt_p,
                          32, k->salt, k->salt_len);
}
static void config_yescrypt(hash_adapter_t *a, const pow_kdf_params_t *k) {
    yescrypt_adapter_config(a, k->scrypt_N, k->scrypt_r, k->scrypt_p,
                            32, k->salt, k->salt_len);
}
static void config_catena(hash_adapter_t *a, const pow_kdf_params_t *k) {
    catena_adapter_config(a, k->lambda, k->garlic, 32, k->salt, k->salt_len);
}
static void config_lyra2(hash_adapter_t *a, const pow_kdf_params_t *k) {
    lyra2_adapter_config(a, k->t_cost, k->nrows, k->ncols,
                         32, k->salt, k->salt_len);
}
static void config_bcrypt(hash_adapter_t *a, const pow_kdf_params_t *k) {
    bcrypt_adapter_config(a, k->work_factor, k->salt, k->salt_len);
}

static void config_balloon(hash_adapter_t *a, const pow_kdf_params_t *k) {
    balloon_adapter_config(a, k->s_cost, k->balloon_t, k->threads,
                           k->salt, k->salt_len);
}

static void config_pomelo(hash_adapter_t *a, const pow_kdf_params_t *k) {
    pomelo_adapter_config(a, k->pomelo_t, k->pomelo_m, 32,
                          k->salt, k->salt_len);
}

static void config_makwa(hash_adapter_t *a, const pow_kdf_params_t *k) {
    makwa_adapter_config(a, k->work_factor, 32, k->salt, k->salt_len);
}

/* XOF shims — output_size not yet wired (extend when adapters gain config API) */
static void config_shake128(hash_adapter_t *a, const pow_kdf_params_t *k) {
    (void)a; (void)k;
}
static void config_shake256(hash_adapter_t *a, const pow_kdf_params_t *k) {
    (void)a; (void)k;
}
static void config_kmac128(hash_adapter_t *a, const pow_kdf_params_t *k) {
    (void)a; (void)k;
}
static void config_kmac256(hash_adapter_t *a, const pow_kdf_params_t *k) {
    (void)a; (void)k;
}

/* =========================================================================
 * Part B — Dispatch table
 * ========================================================================= */

typedef hash_adapter_t *(*create_fn_t)(void);
typedef void            (*config_fn_t)(hash_adapter_t *, const pow_kdf_params_t *);

typedef struct {
    const char  *name;
    create_fn_t  create;
    config_fn_t  config;   /* NULL for plain hashes */
} pow_entry_t;

static const pow_entry_t s_algos[] = {
    /* Plain — 30 entries */
    { "blake2b",    blake2b_adapter_create,    NULL           },
    { "blake2s",    blake2s_adapter_create,    NULL           },
    { "blake3",     blake3_adapter_create,     NULL           },
    { "sha224",     sha224_adapter_create,     NULL           },
    { "sha256",     sha256_adapter_create,     NULL           },
    { "sha384",     sha384_adapter_create,     NULL           },
    { "sha512",     sha512_adapter_create,     NULL           },
    { "sha512-224", sha512_224_adapter_create, NULL           },
    { "sha512-256", sha512_256_adapter_create, NULL           },
    { "sm3",        sm3_adapter_create,        NULL           },
    { "sha3-224",   sha3_224_adapter_create,   NULL           },
    { "sha3-256",   sha3_256_adapter_create,   NULL           },
    { "sha3-384",   sha3_384_adapter_create,   NULL           },
    { "sha3-512",   sha3_512_adapter_create,   NULL           },
    { "keccak256",  keccak256_adapter_create,  NULL           },
    { "skein256",   skein256_adapter_create,   NULL           },
    { "skein512",   skein512_adapter_create,   NULL           },
    { "skein1024",  skein1024_adapter_create,  NULL           },
    { "md2",        md2_adapter_create,        NULL           },
    { "md4",        md4_adapter_create,        NULL           },
    { "md5",        md5_adapter_create,        NULL           },
    { "nt",         nt_adapter_create,         NULL           },
    { "has160",     has160_adapter_create,     NULL           },
    { "ripemd128",  ripemd128_adapter_create,  NULL           },
    { "ripemd160",  ripemd160_adapter_create,  NULL           },
    { "ripemd256",  ripemd256_adapter_create,  NULL           },
    { "ripemd320",  ripemd320_adapter_create,  NULL           },
    { "sha0",       sha0_adapter_create,       NULL           },
    { "sha1",       sha1_adapter_create,       NULL           },
    { "whirlpool",  whirlpool_adapter_create,  NULL           },
    /* XOF — 4 entries */
    { "shake128",   shake128_adapter_create,   config_shake128 },
    { "shake256",   shake256_adapter_create,   config_shake256 },
    { "kmac128",    kmac128_adapter_create,    config_kmac128  },
    { "kmac256",    kmac256_adapter_create,    config_kmac256  },
    /* KDF — 9 unconditional */
    { "argon2id",   argon2id_adapter_create,   config_argon2id },
    { "argon2i",    argon2i_adapter_create,    config_argon2i  },
    { "argon2d",    argon2d_adapter_create,    config_argon2d  },
    { "argon2",     argon2_adapter_create,     config_argon2   },
    { "scrypt",     scrypt_adapter_create,     config_scrypt   },
    { "yescrypt",   yescrypt_adapter_create,   config_yescrypt },
    { "catena",     catena_adapter_create,     config_catena   },
    { "lyra2",      lyra2_adapter_create,      config_lyra2    },
    { "bcrypt",     bcrypt_adapter_create,     config_bcrypt   },
    /* KDF — always compiled */
    { "balloon",    balloon_adapter_create,    config_balloon  },
    { "pomelo",     pomelo_adapter_create,     config_pomelo   },
    { "makwa",      makwa_adapter_create,      config_makwa    },
};

#define N_ALGOS (sizeof(s_algos) / sizeof(s_algos[0]))

/* =========================================================================
 * Part C — Public functions
 * ========================================================================= */

static const pow_entry_t *find_entry(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < N_ALGOS; i++) {
        if (strcmp(s_algos[i].name, name) == 0)
            return &s_algos[i];
    }
    return NULL;
}

int pow_engine_hash(const uint8_t    *in,
                    size_t            len,
                    const pow_config_t *cfg,
                    uint8_t          *out)
{
    if (!cfg || !cfg->algo || !in || !out) return -1;
    const pow_entry_t *e = find_entry(cfg->algo);
    if (!e) return -1;

    hash_adapter_t *a = e->create();
    if (!a) return -1;

    if (e->config)
        e->config(a, &cfg->kdf);

    int rc = a->hash_fn(a->impl, in, len, out, a->digest_size);
    hash_adapter_free(a);
    return rc;
}

size_t pow_engine_digest_size(const pow_config_t *cfg)
{
    if (!cfg || !cfg->algo) return 0;
    const pow_entry_t *e = find_entry(cfg->algo);
    if (!e) return 0;

    hash_adapter_t *a = e->create();
    if (!a) return 0;

    size_t ds = a->digest_size;
    hash_adapter_free(a);
    return ds;
}

int pow_engine_algo_valid(const char *name)
{
    return find_entry(name) ? 1 : 0;
}
