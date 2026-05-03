/* catena_adapter.c — Catena KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "catena.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t  lambda;
    uint8_t  garlic;
    uint32_t key_length;
    uint8_t *salt;
    size_t   salt_len;
    uint8_t  buf[2040];
    size_t   buf_len;
} catena_impl_t;

static int do_hash(catena_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    const uint8_t *s; size_t slen;
    if (p->salt) { s = p->salt; slen = p->salt_len; }
    else {
        uint8_t tmp_salt[16];
        if (kdf_adapter_fill_auto_salt(tmp_salt, sizeof(tmp_salt)) != 0) return -1;
        s = tmp_salt; slen = sizeof(tmp_salt);
        size_t klen = out_len > 0 ? out_len : (size_t)p->key_length;
        return Catena((uint8_t *)(uintptr_t)data, (uint32_t)data_len,
                      s, (uint8_t)slen,
                      NULL, 0,
                      p->lambda, p->garlic, p->garlic,
                      (uint8_t)klen, out);
    }
    size_t klen = out_len > 0 ? out_len : (size_t)p->key_length;
    return Catena((uint8_t *)(uintptr_t)data, (uint32_t)data_len,
                  s, (uint8_t)slen,
                  NULL, 0,              /* associated data */
                  p->lambda, p->garlic, p->garlic,
                  (uint8_t)klen, out);
}

static int catena_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((catena_impl_t *)impl, d, dl, o, ol); }

static void catena_init_fn   (void *impl) { ((catena_impl_t *)impl)->buf_len = 0; }
static void catena_update_fn (void *impl, const uint8_t *d, size_t l)
{
    catena_impl_t *p = (catena_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void catena_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    catena_impl_t *p = (catena_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void catena_destroy_fn(void *impl)
{
    catena_impl_t *p = (catena_impl_t *)impl;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); }
    secure_zero(p->buf, sizeof(p->buf)); free(p);
}

hash_adapter_t *catena_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    catena_impl_t  *p = (catena_impl_t  *)malloc(sizeof(catena_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->lambda = 2; p->garlic = 14; p->key_length = 32;
    p->salt = NULL; p->salt_len = 0; p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 64;
    a->hash_fn = catena_hash_fn; a->init_fn = catena_init_fn;
    a->update_fn = catena_update_fn; a->final_fn = catena_final_fn;
    a->destroy_fn = catena_destroy_fn;
    return a;
}

void catena_adapter_config(hash_adapter_t *a,
                            uint8_t lambda, uint8_t garlic,
                            uint32_t key_length,
                            const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    catena_impl_t *p = (catena_impl_t *)a->impl;
    if (lambda     > 0) p->lambda     = lambda;
    if (garlic     > 0) p->garlic     = garlic;
    if (key_length > 0) { p->key_length = key_length; a->digest_size = key_length; }
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); p->salt = NULL; }
    if (salt && salt_len > 0) {
        p->salt = (uint8_t *)malloc(salt_len);
        if (p->salt) { memcpy(p->salt, salt, salt_len); p->salt_len = salt_len; }
    }
}
