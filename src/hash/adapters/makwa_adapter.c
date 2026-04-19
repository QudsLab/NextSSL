/* makwa_adapter.c — Makwa KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "../memory_hard/makwa/makwa.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

#define MAKWA_SALT_LEN 32

typedef struct {
    uint32_t work_factor;
    size_t   key_length;
    uint8_t  salt[MAKWA_SALT_LEN];
    int      salt_set;
    uint8_t  buf[2040];
    size_t   buf_len;
} makwa_impl_t;

static int do_hash(makwa_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t active_salt[MAKWA_SALT_LEN];
    if (p->salt_set) {
        memcpy(active_salt, p->salt, MAKWA_SALT_LEN);
    } else {
        if (kdf_adapter_fill_auto_salt(active_salt, MAKWA_SALT_LEN) != 0) return -1;
    }
    size_t klen = (out_len < p->key_length ? out_len : p->key_length);
    int rc = makwa_hash(data, data_len, active_salt, MAKWA_SALT_LEN,
                        p->work_factor, out, klen);
    if (out_len > klen) memset(out + klen, 0, out_len - klen);
    secure_zero(active_salt, sizeof(active_salt));
    return rc;
}

static int  makwa_hash_fn   (void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((makwa_impl_t *)impl, d, dl, o, ol); }

static void makwa_init_fn   (void *impl) { ((makwa_impl_t *)impl)->buf_len = 0; }
static void makwa_update_fn (void *impl, const uint8_t *d, size_t l)
{
    makwa_impl_t *p = (makwa_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void makwa_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    makwa_impl_t *p = (makwa_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void makwa_destroy_fn(void *impl)
{
    makwa_impl_t *p = (makwa_impl_t *)impl;
    secure_zero(p->buf, sizeof(p->buf));
    secure_zero(p->salt, sizeof(p->salt));
    free(p);
}

hash_adapter_t *makwa_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    makwa_impl_t   *p = (makwa_impl_t   *)malloc(sizeof(makwa_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->work_factor = 4096; p->key_length = 32;
    p->salt_set = 0; memset(p->salt, 0, sizeof(p->salt));
    p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 64;
    a->hash_fn = makwa_hash_fn; a->init_fn = makwa_init_fn;
    a->update_fn = makwa_update_fn; a->final_fn = makwa_final_fn;
    a->destroy_fn = makwa_destroy_fn;
    return a;
}

void makwa_adapter_config(hash_adapter_t *a,
                           uint32_t work_factor, size_t key_length,
                           const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    makwa_impl_t *p = (makwa_impl_t *)a->impl;
    if (work_factor > 0) p->work_factor = work_factor;
    if (key_length  > 0) { p->key_length = key_length; a->digest_size = key_length; }
    if (salt && salt_len >= MAKWA_SALT_LEN) {
        memcpy(p->salt, salt, MAKWA_SALT_LEN);
        p->salt_set = 1;
    } else {
        p->salt_set = 0;
    }
}
