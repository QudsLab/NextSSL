/* yescrypt_adapter.c — Yescrypt KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "yescrypt.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t N;
    uint32_t r;
    uint32_t p;
    uint32_t key_length;
    uint8_t *salt;
    size_t   salt_len;
    uint8_t  buf[2040];
    size_t   buf_len;
} yescrypt_impl_t;

static int do_hash(yescrypt_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    const uint8_t *s; size_t slen;
    if (p->salt) { s = p->salt; slen = p->salt_len; }
    else {
        uint8_t tmp_salt[16];
        if (kdf_adapter_fill_auto_salt(tmp_salt, sizeof(tmp_salt)) != 0) return -1;
        s = tmp_salt; slen = sizeof(tmp_salt);
        yescrypt_params_t params = { .flags = 0, .N = p->N, .r = p->r, .p = p->p,
                                     .t = 0, .g = 0, .NROM = 0 };
        yescrypt_local_t local;
        yescrypt_init_local(&local);
        int rc = yescrypt_kdf(NULL, &local,
                              data, data_len, s, slen,
                              &params,
                              out, out_len > 0 ? out_len : (size_t)p->key_length);
        yescrypt_free_local(&local);
        return rc;
    }
    yescrypt_params_t params = { .flags = 0, .N = p->N, .r = p->r, .p = p->p,
                                 .t = 0, .g = 0, .NROM = 0 };
    yescrypt_local_t local;
    yescrypt_init_local(&local);
    int rc = yescrypt_kdf(NULL, &local,
                          data, data_len, s, slen,
                          &params,
                          out, out_len > 0 ? out_len : (size_t)p->key_length);
    yescrypt_free_local(&local);
    return rc;
}

static int yescrypt_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((yescrypt_impl_t *)impl, d, dl, o, ol); }

static void yescrypt_init_fn   (void *impl) { ((yescrypt_impl_t *)impl)->buf_len = 0; }
static void yescrypt_update_fn (void *impl, const uint8_t *d, size_t l)
{
    yescrypt_impl_t *p = (yescrypt_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void yescrypt_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    yescrypt_impl_t *p = (yescrypt_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void yescrypt_destroy_fn(void *impl)
{
    yescrypt_impl_t *p = (yescrypt_impl_t *)impl;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); }
    secure_zero(p->buf, sizeof(p->buf)); free(p);
}

hash_adapter_t *yescrypt_adapter_create(void)
{
    hash_adapter_t  *a = (hash_adapter_t  *)malloc(sizeof(hash_adapter_t));
    yescrypt_impl_t *p = (yescrypt_impl_t *)malloc(sizeof(yescrypt_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->N = 16384; p->r = 8; p->p = 1; p->key_length = 32;
    p->salt = NULL; p->salt_len = 0; p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 64;
    a->hash_fn = yescrypt_hash_fn; a->init_fn = yescrypt_init_fn;
    a->update_fn = yescrypt_update_fn; a->final_fn = yescrypt_final_fn;
    a->destroy_fn = yescrypt_destroy_fn;
    return a;
}

void yescrypt_adapter_config(hash_adapter_t *a,
                              uint64_t N, uint32_t r, uint32_t p_param,
                              uint32_t key_length,
                              const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    yescrypt_impl_t *p = (yescrypt_impl_t *)a->impl;
    if (N          > 0) p->N          = N;
    if (r          > 0) p->r          = r;
    if (p_param    > 0) p->p          = p_param;
    if (key_length > 0) { p->key_length = key_length; a->digest_size = key_length; }
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); p->salt = NULL; }
    if (salt && salt_len > 0) {
        p->salt = (uint8_t *)malloc(salt_len);
        if (p->salt) { memcpy(p->salt, salt, salt_len); p->salt_len = salt_len; }
    }
}
