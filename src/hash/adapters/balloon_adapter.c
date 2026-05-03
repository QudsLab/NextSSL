/* balloon_adapter.c — Balloon KDF hash adapter (Plan 40002) */
#include "kdf_adapters.h"
#include "constants.h"   /* defines SALT_LEN, BLOCK_SIZE — must come first */
#include "balloon.h"
#include "hash_state.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t s_cost;
    uint32_t t_cost;
    uint32_t n_threads;
    uint8_t  salt[SALT_LEN];  /* always SALT_LEN=32 bytes */
    int      salt_set;         /* 0 = unset, 1 = fixed */
    uint8_t  buf[2040];
    size_t   buf_len;
} balloon_impl_t;

static int do_hash(balloon_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t active_salt[SALT_LEN];
    if (p->salt_set) {
        memcpy(active_salt, p->salt, SALT_LEN);
    } else {
        if (kdf_adapter_fill_auto_salt(active_salt, SALT_LEN) != 0) return -1;
    }
    struct balloon_options opts = { p->s_cost, p->t_cost, p->n_threads };
    struct hash_state hs;
    if (hash_state_init(&hs, &opts, active_salt) != 0) return -1;
    if (hash_state_fill(&hs, active_salt, data, data_len) != 0) {
        hash_state_free(&hs); return -1;
    }
    for (uint32_t i = 0; i < p->t_cost; i++) hash_state_mix(&hs);
    uint8_t raw[BLOCK_SIZE];
    hash_state_extract(&hs, raw);
    hash_state_free(&hs);

    size_t copy = (out_len > BLOCK_SIZE ? BLOCK_SIZE : out_len);
    memcpy(out, raw, copy);
    if (out_len > BLOCK_SIZE) memset(out + BLOCK_SIZE, 0, out_len - BLOCK_SIZE);
    secure_zero(raw, sizeof(raw));
    secure_zero(active_salt, sizeof(active_salt));
    return 0;
}

static int balloon_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((balloon_impl_t *)impl, d, dl, o, ol); }

static void balloon_init_fn   (void *impl) { ((balloon_impl_t *)impl)->buf_len = 0; }
static void balloon_update_fn (void *impl, const uint8_t *d, size_t l)
{
    balloon_impl_t *p = (balloon_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void balloon_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    balloon_impl_t *p = (balloon_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void balloon_destroy_fn(void *impl)
{
    balloon_impl_t *p = (balloon_impl_t *)impl;
    secure_zero(p->buf, sizeof(p->buf));
    secure_zero(p->salt, sizeof(p->salt));
    free(p);
}

hash_adapter_t *balloon_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    balloon_impl_t *p = (balloon_impl_t *)malloc(sizeof(balloon_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->s_cost = 1024; p->t_cost = 3; p->n_threads = 1;
    p->salt_set = 0; memset(p->salt, 0, sizeof(p->salt));
    p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = BLOCK_SIZE; a->block_size = 64;
    a->hash_fn = balloon_hash_fn; a->init_fn = balloon_init_fn;
    a->update_fn = balloon_update_fn; a->final_fn = balloon_final_fn;
    a->destroy_fn = balloon_destroy_fn;
    return a;
}

void balloon_adapter_config(hash_adapter_t *a,
                             uint32_t s_cost, uint32_t t_cost, uint32_t n_threads,
                             const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    balloon_impl_t *p = (balloon_impl_t *)a->impl;
    if (s_cost   > 0) p->s_cost   = s_cost;
    if (t_cost   > 0) p->t_cost   = t_cost;
    if (n_threads > 0) p->n_threads = n_threads;
    if (salt && salt_len >= SALT_LEN) {
        memcpy(p->salt, salt, SALT_LEN);
        p->salt_set = 1;
    } else {
        p->salt_set = 0;
    }
}
