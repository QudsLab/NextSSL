/* argon2_adapter.c — Generic Argon2 family adapter (Plan 40002)
 *
 * This adapter uses the generic Argon2 API from argon2.h directly.
 * The caller must configure an explicit argon2_type before hashing.
 */
#include "kdf_adapters.h"
#include "../memory_hard/argon2.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t memory;
    uint32_t iterations;
    uint32_t parallelism;
    uint32_t key_length;
    argon2_type type;
    uint8_t *salt;
    size_t   salt_len;
    uint8_t  buf[2040];
    size_t   buf_len;
} argon2_impl_t;

static int do_hash(argon2_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    const uint8_t *salt_bytes;
    size_t current_salt_len;

    if (p->salt) {
        salt_bytes = p->salt;
        current_salt_len = p->salt_len;
    } else {
        uint8_t tmp_salt[16];
        if (kdf_adapter_fill_auto_salt(tmp_salt, sizeof(tmp_salt)) != 0) return -1;
        salt_bytes = tmp_salt;
        current_salt_len = sizeof(tmp_salt);

        if (p->type != Argon2_d && p->type != Argon2_i && p->type != Argon2_id)
            return -1;

        return argon2_hash(p->iterations, p->memory, p->parallelism,
                           data, data_len,
                           salt_bytes, current_salt_len,
                           out, out_len > 0 ? out_len : p->key_length,
                           NULL, 0,
                           p->type,
                           ARGON2_VERSION_NUMBER);
    }

    if (p->type != Argon2_d && p->type != Argon2_i && p->type != Argon2_id)
        return -1;

    return argon2_hash(p->iterations, p->memory, p->parallelism,
                       data, data_len,
                       salt_bytes, current_salt_len,
                       out, out_len > 0 ? out_len : p->key_length,
                       NULL, 0,
                       p->type,
                       ARGON2_VERSION_NUMBER);
}

static int argon2_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((argon2_impl_t *)impl, d, dl, o, ol); }

static void argon2_init_fn(void *impl)
{ ((argon2_impl_t *)impl)->buf_len = 0; }

static void argon2_update_fn(void *impl, const uint8_t *d, size_t l)
{
    argon2_impl_t *p = (argon2_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l);
    p->buf_len += l;
}

static void argon2_final_fn(void *impl, uint8_t *o, size_t ol)
{
    argon2_impl_t *p = (argon2_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len);
    p->buf_len = 0;
}

static void argon2_destroy_fn(void *impl)
{
    argon2_impl_t *p = (argon2_impl_t *)impl;
    if (p->salt) {
        secure_zero(p->salt, p->salt_len);
        free(p->salt);
    }
    secure_zero(p->buf, sizeof(p->buf));
    free(p);
}

hash_adapter_t *argon2_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    argon2_impl_t *p = (argon2_impl_t *)malloc(sizeof(argon2_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }

    p->memory = 65536;
    p->iterations = 2;
    p->parallelism = 1;
    p->key_length = 32;
    p->type = (argon2_type)0xff;
    p->salt = NULL;
    p->salt_len = 0;
    p->buf_len = 0;
    memset(p->buf, 0, sizeof(p->buf));

    a->impl = p;
    a->digest_size = 32;
    a->block_size = 64;
    a->hash_fn = argon2_hash_fn;
    a->init_fn = argon2_init_fn;
    a->update_fn = argon2_update_fn;
    a->final_fn = argon2_final_fn;
    a->destroy_fn = argon2_destroy_fn;
    return a;
}

void argon2_adapter_config(hash_adapter_t *a,
                           uint32_t memory, uint32_t iterations,
                           uint32_t parallelism, uint32_t key_length,
                           const uint8_t *salt, size_t salt_len,
                           argon2_type type)
{
    if (!a || !a->impl) return;
    argon2_impl_t *p = (argon2_impl_t *)a->impl;

    if (memory > 0) p->memory = memory;
    if (iterations > 0) p->iterations = iterations;
    if (parallelism > 0) p->parallelism = parallelism;
    if (key_length > 0) {
        p->key_length = key_length;
        a->digest_size = key_length;
    }
    if (type == Argon2_d || type == Argon2_i || type == Argon2_id)
        p->type = type;

    if (p->salt) {
        secure_zero(p->salt, p->salt_len);
        free(p->salt);
        p->salt = NULL;
        p->salt_len = 0;
    }
    if (salt && salt_len > 0) {
        p->salt = (uint8_t *)malloc(salt_len);
        if (p->salt) {
            memcpy(p->salt, salt, salt_len);
            p->salt_len = salt_len;
        }
    }
}