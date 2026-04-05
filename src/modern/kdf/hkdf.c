/* hkdf.c — HKDF over hash_ops_t vtable (RFC 5869, Plan 202 / Plan 204)
 *
 * Memory discipline (Plan 204):
 *   PRK, T_prev, and HMAC working buffers are wiped via secure_zero()
 *   before returning on every code path.
 */
#include "hkdf.h"
#include "../mac/hmac.h"
#include "../../hash/interface/hash_registry.h"
#include "../../common/secure_zero.h"

#include <string.h>
#include <stdint.h>

/* =========================================================================
 * hkdf_extract_ex
 * ========================================================================= */
int hkdf_extract_ex(const hash_ops_t *hash,
                    const uint8_t    *salt,    size_t salt_len,
                    const uint8_t    *ikm,     size_t ikm_len,
                    uint8_t          *prk)
{
    if (!prk || !ikm || ikm_len == 0) return -1;
    if (!hash) {
        hash_registry_init();
        hash = hash_lookup("sha256");
        if (!hash) return -1;
    }
    if (!(hash->usage_flags & HASH_USAGE_HKDF)) return -1;

    /* RFC 5869 §2.2: if salt not provided, use HashLen zeros */
    uint8_t zero_salt[64]; /* max digest_size of any built-in hash */
    if (!salt || salt_len == 0) {
        if (hash->digest_size > sizeof(zero_salt)) return -1;
        memset(zero_salt, 0, hash->digest_size);
        salt     = zero_salt;
        salt_len = hash->digest_size;
    }

    /* PRK = HMAC-Hash(salt, IKM) */
    int r = hmac_compute(hash, salt, salt_len, ikm, ikm_len, prk);
    secure_zero(zero_salt, sizeof(zero_salt));
    return r;
}

/* =========================================================================
 * hkdf_expand_ex
 * ========================================================================= */
int hkdf_expand_ex(const hash_ops_t *hash,
                   const uint8_t    *prk,   size_t prk_len,
                   const uint8_t    *info,  size_t info_len,
                   uint8_t          *okm,   size_t okm_len)
{
    if (!prk || prk_len == 0 || !okm || okm_len == 0) return -1;
    if (!hash) {
        hash_registry_init();
        hash = hash_lookup("sha256");
        if (!hash) return -1;
    }
    if (!(hash->usage_flags & HASH_USAGE_HKDF)) return -1;

    /* Ceiling check: okm_len ≤ 255 × HashLen (RFC 5869 §2.3) */
    if (okm_len > 255u * hash->digest_size) return -1;

    uint8_t t_prev[64];  /* T(i-1), max 64 bytes */
    uint8_t t_curr[64];  /* T(i) output */
    size_t  hash_len = hash->digest_size;
    size_t  produced = 0;
    uint8_t counter  = 1;

    memset(t_prev, 0, sizeof(t_prev));

    while (produced < okm_len) {
        /* T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i) */
        hmac_ctx_t hctx;
        hmac_init(&hctx, hash, prk, prk_len);
        if (counter > 1)
            hmac_update(&hctx, t_prev, hash_len);
        if (info && info_len > 0)
            hmac_update(&hctx, info, info_len);
        hmac_update(&hctx, &counter, 1);
        hmac_final(&hctx, t_curr);

        size_t copy = okm_len - produced;
        if (copy > hash_len) copy = hash_len;
        memcpy(okm + produced, t_curr, copy);

        memcpy(t_prev, t_curr, hash_len);
        produced += copy;
        counter++;
    }

    secure_zero(t_prev, sizeof(t_prev));
    secure_zero(t_curr, sizeof(t_curr));
    return 0;
}

/* =========================================================================
 * hkdf_ex — combined Extract + Expand
 * ========================================================================= */
int hkdf_ex(const hash_ops_t *hash,
            const uint8_t    *salt,    size_t salt_len,
            const uint8_t    *ikm,     size_t ikm_len,
            const uint8_t    *info,    size_t info_len,
            uint8_t          *okm,     size_t okm_len)
{
    if (!okm || okm_len == 0 || !ikm || ikm_len == 0) return -1;
    if (!hash) {
        hash_registry_init();
        hash = hash_lookup("sha256");
        if (!hash) return -1;
    }
    if (!(hash->usage_flags & HASH_USAGE_HKDF)) return -1;

    uint8_t prk[64]; /* PRK ≤ 64 bytes */
    if (hash->digest_size > sizeof(prk)) return -1;

    int r = hkdf_extract_ex(hash, salt, salt_len, ikm, ikm_len, prk);
    if (r == 0)
        r = hkdf_expand_ex(hash, prk, hash->digest_size, info, info_len, okm, okm_len);

    secure_zero(prk, sizeof(prk));
    return r;
}

/* =========================================================================
 * hkdf_expand_label_ex — RFC 8446 §7.1
 * ========================================================================= */
int hkdf_expand_label_ex(const hash_ops_t *hash,
                         const uint8_t    *secret,    size_t  secret_len,
                         const char       *label,
                         const uint8_t    *context,   size_t  context_len,
                         uint8_t          *okm,       size_t  okm_len)
{
    if (!secret || secret_len == 0 || !label || !okm || okm_len == 0) return -1;
    if (!hash) {
        hash_registry_init();
        hash = hash_lookup("sha256");
        if (!hash) return -1;
    }
    if (!(hash->usage_flags & HASH_USAGE_HKDF)) return -1;

    /* Build HkdfLabel:
     *   uint16 Length   — okm_len  (big-endian)
     *   opaque label    — "tls13 " || label
     *   opaque context  — uint8 context_len || context
     */
    size_t label_len = strlen(label);
    /* "tls13 " prefix is 6 bytes */
    size_t prefix_len = 6;
    size_t lbl_total  = prefix_len + label_len;
    if (lbl_total > 255 || context_len > 255) return -1;

    /* Stack-allocate the HkdfLabel buffer (max ~512 bytes) */
    uint8_t hkdf_label[2 + 1 + 255 + 1 + 255];
    size_t  pos = 0;

    /* Length (2 bytes, big-endian) */
    hkdf_label[pos++] = (uint8_t)((okm_len >> 8) & 0xff);
    hkdf_label[pos++] = (uint8_t)( okm_len        & 0xff);

    /* Label length + "tls13 " + label */
    hkdf_label[pos++] = (uint8_t)lbl_total;
    memcpy(hkdf_label + pos, "tls13 ", prefix_len); pos += prefix_len;
    memcpy(hkdf_label + pos, label, label_len);      pos += label_len;

    /* Context length + context */
    hkdf_label[pos++] = (uint8_t)context_len;
    if (context && context_len > 0) {
        memcpy(hkdf_label + pos, context, context_len);
        pos += context_len;
    }

    int r = hkdf_expand_ex(hash, secret, secret_len,
                            hkdf_label, pos,
                            okm, okm_len);
    secure_zero(hkdf_label, sizeof(hkdf_label));
    return r;
}
