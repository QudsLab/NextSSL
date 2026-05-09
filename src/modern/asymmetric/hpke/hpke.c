/* hpke.c — Hybrid Public Key Encryption (RFC 9180)
 *
 * Implements HPKE base mode with X25519-HKDF-SHA256-AES128GCM.
 *
 * RFC 9180 §4 key schedule:
 *   Ks (shared_secret), enc = Encap(pkR)
 *   prk = LabeledExtract("shared_secret", ks)
 *   key = LabeledExpand(prk, "key", ..., Nk)
 *   base_nonce = LabeledExpand(prk, "base_nonce", ..., Nn)
 *   exporter_secret = LabeledExpand(prk, "exp", ..., Nh)
 *
 * TODO: Implement full LabeledExtract / LabeledExpand per RFC 9180 §4.
 *       This file provides a structurally correct HPKE implementation using
 *       direct HKDF calls as approximation pending the labeled variants.
 */
#include "hpke.h"
#include "../../kdf/hkdf/hkdf.h"
#include "../../aead/aes_gcm/aes_gcm.h"
#include "../p256/p256.h"
#include <stdlib.h>
#include <string.h>

extern int x25519(uint8_t out[32], const uint8_t k[32], const uint8_t u[32]);
extern int x25519_base(uint8_t pub[32], const uint8_t k[32]);
extern int rng_fill(void *buf, size_t len);

#define AES128GCM_KEY_SIZE  16u
#define AES128GCM_NONCE_SIZE 12u
#define AES128GCM_TAG_SIZE  16u
#define HKDF_SHA256_HASH_SIZE 32u

struct hpke_sender_ctx {
    uint8_t key[AES128GCM_KEY_SIZE];
    uint8_t base_nonce[AES128GCM_NONCE_SIZE];
    uint64_t seq;
};

struct hpke_recipient_ctx {
    uint8_t key[AES128GCM_KEY_SIZE];
    uint8_t base_nonce[AES128GCM_NONCE_SIZE];
    uint64_t seq;
};

/* Build the HPKE suite context bytes (kem_id || kdf_id || aead_id) */
static void suite_id(hpke_suite_t s, uint8_t out[6])
{
    out[0] = 'H'; out[1] = 'P'; out[2] = 'K'; out[3] = 'E';
    out[4] = (uint8_t)(s.kem_id  >> 8); out[5] = (uint8_t)(s.kem_id);
    /* Note: RFC uses 10-byte suite_id; this is a simplified version */
    (void)s;
}

/* HPKE key schedule for base mode (simplified HKDF approximation) */
static int key_schedule_base(const uint8_t *shared_secret, size_t ss_len,
                               const uint8_t *enc, size_t enc_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t key[AES128GCM_KEY_SIZE],
                               uint8_t base_nonce[AES128GCM_NONCE_SIZE])
{
    /* Concatenate enc || info as salt-like material */
    uint8_t ctx[512];
    size_t ctx_len = 0;
    if (enc_len + info_len > sizeof(ctx) - 32) return -1;
    if (enc) { memcpy(ctx + ctx_len, enc, enc_len); ctx_len += enc_len; }
    if (info) { memcpy(ctx + ctx_len, info, info_len); ctx_len += info_len; }

    uint8_t okm[AES128GCM_KEY_SIZE + AES128GCM_NONCE_SIZE];
    int ret = hkdf_ex(NULL, ctx, ctx_len,
                       shared_secret, ss_len,
                       (const uint8_t *)"HPKE-v1", 7,
                       okm, sizeof(okm));
    if (ret != 0) return -1;
    memcpy(key,        okm, AES128GCM_KEY_SIZE);
    memcpy(base_nonce, okm + AES128GCM_KEY_SIZE, AES128GCM_NONCE_SIZE);
    return 0;
}

static void compute_nonce(const uint8_t base_nonce[AES128GCM_NONCE_SIZE],
                           uint64_t seq, uint8_t nonce[AES128GCM_NONCE_SIZE])
{
    memcpy(nonce, base_nonce, AES128GCM_NONCE_SIZE);
    /* XOR the last 8 bytes with seq (big-endian) */
    for (int i = 0; i < 8; i++)
        nonce[AES128GCM_NONCE_SIZE - 8 + i] ^= (uint8_t)(seq >> (56 - 8 * i));
}

hpke_sender_ctx_t *hpke_sender_setup(
        hpke_suite_t    suite,
        hpke_mode_t     mode,
        const uint8_t  *recipient_pub, size_t pub_len,
        const uint8_t  *info,          size_t info_len,
        const uint8_t  *psk,           size_t psk_len,
        const uint8_t  *psk_id,        size_t psk_id_len,
        uint8_t        *enc_buf,       size_t *enc_len)
{
    if (!recipient_pub || !enc_buf || !enc_len) return NULL;
    /* Only BASE mode supported; PSK/Auth TODO */
    if (mode != HPKE_MODE_BASE) return NULL;
    (void)psk; (void)psk_len; (void)psk_id; (void)psk_id_len;

    uint8_t shared_secret[32];

    if (suite.kem_id == HPKE_KEM_X25519_HKDF_SHA256) {
        if (*enc_len < 32) return NULL;
        uint8_t eph_priv[32], eph_pub[32];
        if (rng_fill(eph_priv, 32) != 0) return NULL;
        if (x25519_base(eph_pub, eph_priv) != 0) return NULL;
        if (x25519(shared_secret, eph_priv, recipient_pub) != 0) {
            memset(eph_priv, 0, 32); return NULL;
        }
        memcpy(enc_buf, eph_pub, 32);
        *enc_len = 32;
        memset(eph_priv, 0, 32);
    } else if (suite.kem_id == HPKE_KEM_P256_HKDF_SHA256) {
        if (*enc_len < 64) return NULL;
        uint8_t eph_priv[32], eph_pub[64];
        if (p256_keygen(eph_priv, eph_pub) != 0) return NULL;
        if (p256_ecdh(recipient_pub, eph_priv, shared_secret) != 0) {
            memset(eph_priv, 0, 32); return NULL;
        }
        memcpy(enc_buf, eph_pub, 64);
        *enc_len = 64;
        memset(eph_priv, 0, 32);
    } else {
        return NULL;
    }

    hpke_sender_ctx_t *ctx = (hpke_sender_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) { memset(shared_secret, 0, 32); return NULL; }

    if (key_schedule_base(shared_secret, 32, enc_buf, *enc_len,
                           info, info_len, ctx->key, ctx->base_nonce) != 0) {
        memset(shared_secret, 0, 32); free(ctx); return NULL;
    }
    memset(shared_secret, 0, 32);
    ctx->seq = 0;
    return ctx;
}

int hpke_seal(hpke_sender_ctx_t *ctx,
              const uint8_t *aad,   size_t aad_len,
              const uint8_t *pt,    size_t pt_len,
              uint8_t       *ct,    size_t *ct_len)
{
    if (!ctx || !ct || !ct_len) return -1;
    if (*ct_len < pt_len + AES128GCM_TAG_SIZE) return -1;

    uint8_t nonce[AES128GCM_NONCE_SIZE];
    compute_nonce(ctx->base_nonce, ctx->seq, nonce);

    size_t tag_out = AES128GCM_TAG_SIZE;
    int ret = aes_gcm_encrypt(ctx->key, 128, nonce, AES128GCM_NONCE_SIZE,
                               aad, aad_len,
                               pt, pt_len,
                               ct, ct + pt_len, &tag_out);
    if (ret != 0) return -1;
    ctx->seq++;
    *ct_len = pt_len + AES128GCM_TAG_SIZE;
    return 0;
}

void hpke_sender_ctx_free(hpke_sender_ctx_t *ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

hpke_recipient_ctx_t *hpke_recipient_setup(
        hpke_suite_t    suite,
        hpke_mode_t     mode,
        const uint8_t  *enc_buf,        size_t enc_len,
        const uint8_t  *recipient_priv, size_t priv_len,
        const uint8_t  *info,           size_t info_len,
        const uint8_t  *psk,            size_t psk_len,
        const uint8_t  *psk_id,         size_t psk_id_len)
{
    if (!enc_buf || !recipient_priv) return NULL;
    if (mode != HPKE_MODE_BASE) return NULL;
    (void)psk; (void)psk_len; (void)psk_id; (void)psk_id_len; (void)priv_len;

    uint8_t shared_secret[32];

    if (suite.kem_id == HPKE_KEM_X25519_HKDF_SHA256) {
        if (enc_len < 32) return NULL;
        if (x25519(shared_secret, recipient_priv, enc_buf) != 0) return NULL;
    } else if (suite.kem_id == HPKE_KEM_P256_HKDF_SHA256) {
        if (enc_len < 64) return NULL;
        if (p256_ecdh(enc_buf, recipient_priv, shared_secret) != 0) return NULL;
    } else {
        return NULL;
    }

    hpke_recipient_ctx_t *ctx = (hpke_recipient_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) { memset(shared_secret, 0, 32); return NULL; }

    if (key_schedule_base(shared_secret, 32, enc_buf, enc_len,
                           info, info_len, ctx->key, ctx->base_nonce) != 0) {
        memset(shared_secret, 0, 32); free(ctx); return NULL;
    }
    memset(shared_secret, 0, 32);
    ctx->seq = 0;
    return ctx;
}

int hpke_open(hpke_recipient_ctx_t *ctx,
              const uint8_t *aad,  size_t aad_len,
              const uint8_t *ct,   size_t ct_len,
              uint8_t       *pt,   size_t *pt_len)
{
    if (!ctx || !ct || !pt || !pt_len) return -1;
    if (ct_len < AES128GCM_TAG_SIZE) return -1;
    size_t msg_len = ct_len - AES128GCM_TAG_SIZE;
    if (*pt_len < msg_len) return -1;

    uint8_t nonce[AES128GCM_NONCE_SIZE];
    compute_nonce(ctx->base_nonce, ctx->seq, nonce);

    int ret = aes_gcm_decrypt(ctx->key, 128, nonce, AES128GCM_NONCE_SIZE,
                               aad, aad_len,
                               ct, msg_len,
                               ct + msg_len, AES128GCM_TAG_SIZE,
                               pt);
    if (ret != 0) return -1;
    ctx->seq++;
    *pt_len = msg_len;
    return 0;
}

void hpke_recipient_ctx_free(hpke_recipient_ctx_t *ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}
