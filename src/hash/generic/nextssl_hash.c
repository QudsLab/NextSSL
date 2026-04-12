/* nextssl_hash.c — Way 1: Generic single-entry-point hash dispatch (Plan 40002)
 *
 * Dispatches to any of the 41+ supported algorithms by name. For plain hashes
 * it uses the seed registry (hash_lookup_by_name) + plain_hash_adapter_create().
 * For KDF algorithms it uses a static factory table.
 */
#include "nextssl_hash.h"
#include "../adapters/hash_adapter.h"
#include "../adapters/plain_hash_adapter.h"
#include "../adapters/kdf_adapters.h"
#include "../../seed/hash/hash_registry.h"
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Static zero-valued config used when the caller passes config=NULL.
 * KDF adapters treat 0 as "keep default", so this is safe.
 * -------------------------------------------------------------------------*/
static const nextssl_hash_config_t s_zero_config;

/* -------------------------------------------------------------------------
 * KDF factory entry: name → create function + apply-config function
 * -------------------------------------------------------------------------*/
typedef hash_adapter_t *(*kdf_create_fn)(void);
typedef void            (*kdf_apply_fn) (hash_adapter_t *a,
                                         const nextssl_hash_config_t *cfg);

typedef struct {
    const char    *name;
    kdf_create_fn  create;
    kdf_apply_fn   apply;
} kdf_factory_t;

/* ---- Per-KDF apply helpers -------------------------------------------- */

static void apply_argon2id(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ argon2id_adapter_config(a, c->memory, c->iterations, c->parallelism, c->key_length, c->salt, c->salt_len); }

static void apply_argon2i(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ argon2i_adapter_config(a, c->memory, c->iterations, c->parallelism, c->key_length, c->salt, c->salt_len); }

static void apply_argon2d(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ argon2d_adapter_config(a, c->memory, c->iterations, c->parallelism, c->key_length, c->salt, c->salt_len); }

static void apply_argon2(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ argon2_adapter_config(a, c->memory, c->iterations, c->parallelism, c->key_length, c->salt, c->salt_len); }

static void apply_scrypt(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ scrypt_adapter_config(a, c->N, c->r, c->p, c->key_length, c->salt, c->salt_len); }

static void apply_yescrypt(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ yescrypt_adapter_config(a, c->N, c->r, c->p, c->key_length, c->salt, c->salt_len); }

static void apply_bcrypt(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ bcrypt_adapter_config(a, c->work_factor, c->salt, c->salt_len); }

static void apply_catena(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ catena_adapter_config(a, c->lambda, c->garlic, c->key_length, c->salt, c->salt_len); }

static void apply_lyra2(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ lyra2_adapter_config(a, c->t_cost, c->nrows, c->ncols, c->key_length, c->salt, c->salt_len); }

static void apply_balloon(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ balloon_adapter_config(a, c->s_cost, (uint32_t)c->iterations, c->n_threads, c->salt, c->salt_len); }

static void apply_pomelo(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ pomelo_adapter_config(a, c->t_cost_u, c->m_cost_u, c->key_length, c->salt, c->salt_len); }

static void apply_makwa(hash_adapter_t *a, const nextssl_hash_config_t *c)
{ makwa_adapter_config(a, c->work_factor, c->key_length, c->salt, c->salt_len); }

/* ---- Static factory table --------------------------------------------- */
static const kdf_factory_t s_kdf_table[] = {
    { "argon2id",  argon2id_adapter_create,  apply_argon2id  },
    { "argon2i",   argon2i_adapter_create,   apply_argon2i   },
    { "argon2d",   argon2d_adapter_create,   apply_argon2d   },
    { "argon2",    argon2_adapter_create,    apply_argon2    },
    { "scrypt",    scrypt_adapter_create,    apply_scrypt    },
    { "yescrypt",  yescrypt_adapter_create,  apply_yescrypt  },
    { "bcrypt",    bcrypt_adapter_create,    apply_bcrypt    },
    { "catena",    catena_adapter_create,    apply_catena    },
    { "lyra2",     lyra2_adapter_create,     apply_lyra2     },
    { "balloon",   balloon_adapter_create,   apply_balloon   },
    { "pomelo",    pomelo_adapter_create,    apply_pomelo    },
    { "makwa",     makwa_adapter_create,     apply_makwa     },
};
#define KDF_TABLE_SIZE (sizeof(s_kdf_table) / sizeof(s_kdf_table[0]))

/* =====================================================================
 * nextssl_hash — one-shot dispatch
 * ===================================================================== */
int nextssl_hash(const char    *algo_name,
                 const uint8_t *data,     size_t data_len,
                 uint8_t       *out,      size_t out_len,
                 const nextssl_hash_config_t *config)
{
    if (!algo_name || !data || !out || out_len == 0) return -1;
    if (!config) config = &s_zero_config;

    /* 1. Check KDF table first (KDF names don't appear in plain registry) */
    for (size_t i = 0; i < KDF_TABLE_SIZE; i++) {
        if (strcmp(algo_name, s_kdf_table[i].name) == 0) {
            hash_adapter_t *a = s_kdf_table[i].create();
            if (!a) return -2;
            s_kdf_table[i].apply(a, config);
            int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
            hash_adapter_free(a);
            return (rc == 0) ? 0 : -2;
        }
    }

    /* 2. Try plain hash registry */
    const hash_ops_t *ops = hash_lookup_by_name(algo_name);
    if (!ops) return -1;

    hash_adapter_t *a = plain_hash_adapter_create(ops);
    if (!a) return -2;
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a);
    return (rc == 0) ? 0 : -2;
}
