/* lyra2_adapter.c — Lyra2 KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "Lyra2.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t t_cost;
    uint32_t nrows;
    uint32_t ncols;
    uint32_t key_length;
    uint8_t *salt;
    size_t   salt_len;
    uint8_t  buf[2040];
    size_t   buf_len;
} lyra2_impl_t;

static int do_hash(lyra2_impl_t *p,
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
        return LYRA2(out, (uint64_t)klen,
                     data, (uint64_t)data_len,
                     s, (uint64_t)slen,
                     p->t_cost, p->nrows, p->ncols);
    }
    size_t klen = out_len > 0 ? out_len : (size_t)p->key_length;
    return LYRA2(out, (uint64_t)klen,
                 data, (uint64_t)data_len,
                 s, (uint64_t)slen,
                 p->t_cost, p->nrows, p->ncols);
}

static int lyra2_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((lyra2_impl_t *)impl, d, dl, o, ol); }

static void lyra2_init_fn   (void *impl) { ((lyra2_impl_t *)impl)->buf_len = 0; }
static void lyra2_update_fn (void *impl, const uint8_t *d, size_t l)
{
    lyra2_impl_t *p = (lyra2_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void lyra2_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    lyra2_impl_t *p = (lyra2_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void lyra2_destroy_fn(void *impl)
{
    lyra2_impl_t *p = (lyra2_impl_t *)impl;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); }
    secure_zero(p->buf, sizeof(p->buf)); free(p);
}

hash_adapter_t *lyra2_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    lyra2_impl_t   *p = (lyra2_impl_t   *)malloc(sizeof(lyra2_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->t_cost = 1; p->nrows = 8; p->ncols = 256; p->key_length = 32;
    p->salt = NULL; p->salt_len = 0; p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 64;
    a->hash_fn = lyra2_hash_fn; a->init_fn = lyra2_init_fn;
    a->update_fn = lyra2_update_fn; a->final_fn = lyra2_final_fn;
    a->destroy_fn = lyra2_destroy_fn;
    return a;
}

void lyra2_adapter_config(hash_adapter_t *a,
                           uint64_t t_cost, uint32_t nrows, uint32_t ncols,
                           uint32_t key_length,
                           const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    lyra2_impl_t *p = (lyra2_impl_t *)a->impl;
    if (t_cost     > 0) p->t_cost     = t_cost;
    if (nrows      > 0) p->nrows      = nrows;
    if (ncols      > 0) p->ncols      = ncols;
    if (key_length > 0) { p->key_length = key_length; a->digest_size = key_length; }
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); p->salt = NULL; }
    if (salt && salt_len > 0) {
        p->salt = (uint8_t *)malloc(salt_len);
        if (p->salt) { memcpy(p->salt, salt, salt_len); p->salt_len = salt_len; }
    }
}
