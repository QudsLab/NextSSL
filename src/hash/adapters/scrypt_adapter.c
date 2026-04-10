/* scrypt_adapter.c — Scrypt KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "../memory_hard/scrypt/crypto_scrypt.h"
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
} scrypt_impl_t;

static int do_hash(scrypt_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t tmp_salt[16];
    const uint8_t *s; size_t slen;
    if (p->salt) { s = p->salt; slen = p->salt_len; }
    else {
        if (entropy_getrandom(tmp_salt, sizeof(tmp_salt)) != 0) return -1;
        s = tmp_salt; slen = sizeof(tmp_salt);
    }
    return crypto_scrypt(data, data_len, s, slen,
                         p->N, p->r, p->p,
                         out, out_len > 0 ? out_len : (size_t)p->key_length);
}

static int scrypt_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((scrypt_impl_t *)impl, d, dl, o, ol); }

static void scrypt_init_fn   (void *impl) { ((scrypt_impl_t *)impl)->buf_len = 0; }
static void scrypt_update_fn (void *impl, const uint8_t *d, size_t l)
{
    scrypt_impl_t *p = (scrypt_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void scrypt_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    scrypt_impl_t *p = (scrypt_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void scrypt_destroy_fn(void *impl)
{
    scrypt_impl_t *p = (scrypt_impl_t *)impl;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); }
    secure_zero(p->buf, sizeof(p->buf)); free(p);
}

hash_adapter_t *scrypt_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    scrypt_impl_t  *p = (scrypt_impl_t  *)malloc(sizeof(scrypt_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->N = 16384; p->r = 8; p->p = 1; p->key_length = 32;
    p->salt = NULL; p->salt_len = 0; p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 64;
    a->hash_fn = scrypt_hash_fn; a->init_fn = scrypt_init_fn;
    a->update_fn = scrypt_update_fn; a->final_fn = scrypt_final_fn;
    a->destroy_fn = scrypt_destroy_fn;
    return a;
}

void scrypt_adapter_config(hash_adapter_t *a,
                            uint64_t N, uint32_t r, uint32_t p_param,
                            uint32_t key_length,
                            const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    scrypt_impl_t *p = (scrypt_impl_t *)a->impl;
    if (N         > 0) p->N          = N;
    if (r         > 0) p->r          = r;
    if (p_param   > 0) p->p          = p_param;
    if (key_length > 0) { p->key_length = key_length; a->digest_size = key_length; }
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); p->salt = NULL; }
    if (salt && salt_len > 0) {
        p->salt = (uint8_t *)malloc(salt_len);
        if (p->salt) { memcpy(p->salt, salt, salt_len); p->salt_len = salt_len; }
    }
}
