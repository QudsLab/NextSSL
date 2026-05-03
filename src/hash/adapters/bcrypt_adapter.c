/* bcrypt_adapter.c — Bcrypt KDF hash adapter (Plan 40002)
 *
 * Bcrypt generates its own setting string internally. The adapter's salt
 * field holds 16 bytes of caller-provided raw salt that are base64-encoded
 * into the setting string.
 *   salt == NULL  →  invalid; caller must provide 16 bytes explicitly
 *   salt != NULL  →  user-supplied 16 bytes (deterministic output)
 *
 * Output: 32 raw bytes derived from the 31-char bcrypt base64 hash (same
 * decode method as bcrypt_ops.c).
 */
#include "kdf_adapters.h"
#include "crypt_blowfish.h"
#include "crypt_gensalt.h"
#include "../../seed/random/entropy.h"
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t work_factor;  /* bcrypt cost: rounds = 2^work_factor */
    uint8_t *salt;         /* 16 bytes; NULL = random */
    size_t   salt_len;
    uint8_t  buf[2040];    /* password accumulator */
    size_t   buf_len;
} bcrypt_impl_t;

/* bcrypt base64 decode table (same as bcrypt_ops.c) */
static const int8_t s_b64dec[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 0, 1,
    54,55,56,57,58,59,60,61,62,63,-1,-1,-1,-1,-1,-1,
    -1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,-1,-1,-1,-1,-1,
    -1,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,
    43,44,45,46,47,48,49,50,51,52,53,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static void b64_decode_tail(const char *s, size_t slen, uint8_t *out, size_t outlen)
{
    size_t si = 0, oi = 0;
    while (si + 2 < slen && oi < outlen) {
        int a = s_b64dec[(unsigned char)s[si]];
        int b = s_b64dec[(unsigned char)s[si+1]];
        int c = s_b64dec[(unsigned char)s[si+2]];
        if (a < 0 || b < 0 || c < 0) break;
        out[oi++] = (uint8_t)((a << 2) | (b >> 4));
        if (oi < outlen) out[oi++] = (uint8_t)((b << 4) | (c >> 2));
        if (si + 3 < slen && oi < outlen) {
            int d = s_b64dec[(unsigned char)s[si+3]];
            if (d >= 0) out[oi++] = (uint8_t)((c << 6) | d);
        }
        si += 4;
    }
}

static int do_hash(bcrypt_impl_t *p,
                   const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len)
{
    /* Use caller-provided salt when present, otherwise generate 16 random bytes. */
    uint8_t raw_salt[16];
    if (p->salt && p->salt_len >= sizeof(raw_salt)) {
        memcpy(raw_salt, p->salt, 16);
    } else {
        if (kdf_adapter_fill_auto_salt(raw_salt, sizeof(raw_salt)) != 0) return -1;
    }

    /* Build setting string: "$2b$XX$" + 22-char base64 salt */
    char setting[32];
    char *ret = _crypt_gensalt_traditional_rn("$2b$", (unsigned long)p->work_factor,
                                              (const char *)raw_salt, 16,
                                              setting, (int)sizeof(setting));
    if (!ret) return -1;

    /* Null-terminate the password */
    uint8_t pwbuf[2041];
    size_t  pwlen = data_len < 2040 ? data_len : 2040;
    memcpy(pwbuf, data, pwlen);
    pwbuf[pwlen] = '\0';

    /* Run bcrypt */
    char output[64];
    memset(output, 0, sizeof(output));
    _crypt_blowfish_rn((const char *)pwbuf, setting, output, (int)sizeof(output));

    /* Decode 31-char hash tail to 32 raw bytes */
    memset(out, 0, out_len > 32 ? 32 : out_len);
    if (output[0] != '\0') {
        b64_decode_tail(output + 29, 31, out, 32);
    }

    secure_zero(pwbuf, sizeof(pwbuf));
    secure_zero(raw_salt, sizeof(raw_salt));
    return 0;
}

static int bcrypt_hash_fn(void *impl, const uint8_t *d, size_t dl, uint8_t *o, size_t ol)
{ return do_hash((bcrypt_impl_t *)impl, d, dl, o, ol); }

static void bcrypt_init_fn   (void *impl) { ((bcrypt_impl_t *)impl)->buf_len = 0; }
static void bcrypt_update_fn (void *impl, const uint8_t *d, size_t l)
{
    bcrypt_impl_t *p = (bcrypt_impl_t *)impl;
    size_t room = sizeof(p->buf) - p->buf_len;
    if (l > room) l = room;
    memcpy(p->buf + p->buf_len, d, l); p->buf_len += l;
}
static void bcrypt_final_fn  (void *impl, uint8_t *o, size_t ol)
{
    bcrypt_impl_t *p = (bcrypt_impl_t *)impl;
    do_hash(p, p->buf, p->buf_len, o, ol);
    secure_zero(p->buf, p->buf_len); p->buf_len = 0;
}
static void bcrypt_destroy_fn(void *impl)
{
    bcrypt_impl_t *p = (bcrypt_impl_t *)impl;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); }
    secure_zero(p->buf, sizeof(p->buf)); free(p);
}

hash_adapter_t *bcrypt_adapter_create(void)
{
    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    bcrypt_impl_t  *p = (bcrypt_impl_t  *)malloc(sizeof(bcrypt_impl_t));
    if (!a || !p) { free(a); free(p); return NULL; }
    p->work_factor = 10; p->salt = NULL; p->salt_len = 0;
    p->buf_len = 0; memset(p->buf, 0, sizeof(p->buf));
    a->impl = p; a->digest_size = 32; a->block_size = 72; /* bcrypt max pw len */
    a->hash_fn = bcrypt_hash_fn; a->init_fn = bcrypt_init_fn;
    a->update_fn = bcrypt_update_fn; a->final_fn = bcrypt_final_fn;
    a->destroy_fn = bcrypt_destroy_fn;
    return a;
}

void bcrypt_adapter_config(hash_adapter_t *a,
                            uint32_t work_factor,
                            const uint8_t *salt, size_t salt_len)
{
    if (!a || !a->impl) return;
    bcrypt_impl_t *p = (bcrypt_impl_t *)a->impl;
    if (work_factor > 0) p->work_factor = work_factor;
    if (p->salt) { secure_zero(p->salt, p->salt_len); free(p->salt); p->salt = NULL; }
    /* bcrypt salt must be exactly 16 bytes */
    if (salt && salt_len >= 16) {
        p->salt = (uint8_t *)malloc(16);
        if (p->salt) { memcpy(p->salt, salt, 16); p->salt_len = 16; }
    }
}
