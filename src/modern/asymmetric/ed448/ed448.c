/* ed448.c — Ed448-Goldilocks EdDSA surface (RFC 8032 §5.2)
 *
 * Delegates to wolfSSL-derived _curve448_backend.
 */
#include "ed448.h"
#include "../_curve448_backend/ed448.h"
#include "../_curve448_backend/wolf_shim.h"
#include <string.h>

extern int rng_fill(void *buf, size_t len);

/* Shim WC_RNG to use project entropy */
static WC_RNG g_rng;
static int    g_rng_init = 0;
static WC_RNG *get_rng(void)
{
    if (!g_rng_init) {
        wc_InitRng(&g_rng);
        g_rng_init = 1;
    }
    return &g_rng;
}

int ed448_keygen(uint8_t private_key[ED448_PRIVATE_KEY_SIZE],
                 uint8_t public_key[ED448_PUBLIC_KEY_SIZE])
{
    if (!private_key || !public_key) return -1;

    ed448_key key;
    if (wc_ed448_init(&key) != 0) return -1;

    int ret = -1;
    if (wc_ed448_make_key(get_rng(), ED448_KEY_SIZE, &key) != 0) goto done;

    word32 pub_sz = ED448_PUBLIC_KEY_SIZE;
    if (wc_ed448_make_public(&key, public_key, pub_sz) != 0) goto done;

    /* Extract private scalar from key.k (first 57 bytes) */
    memcpy(private_key, key.k, ED448_PRIVATE_KEY_SIZE);
    ret = 0;
done:
    wc_ed448_free(&key);
    return ret;
}

int ed448_sign(const uint8_t *private_key, size_t priv_len,
               const uint8_t *public_key,  size_t pub_len,
               const uint8_t *msg,         size_t msg_len,
               const uint8_t *context,     uint8_t context_len,
               uint8_t        sig[ED448_SIGNATURE_SIZE])
{
    if (!private_key || !public_key || (!msg && msg_len) || !sig) return -1;
    if (priv_len != ED448_PRIVATE_KEY_SIZE || pub_len != ED448_PUBLIC_KEY_SIZE) return -1;

    ed448_key key;
    if (wc_ed448_init(&key) != 0) return -1;

    int ret = -1;
    if (wc_ed448_import_private_key(private_key, priv_len,
                                     public_key,  pub_len, &key) != 0) goto done;
    word32 sig_sz = ED448_SIGNATURE_SIZE;
    if (wc_ed448_sign_msg(msg, (word32)msg_len, sig, &sig_sz, &key,
                          context, context_len) != 0) goto done;
    ret = 0;
done:
    wc_ed448_free(&key);
    return ret;
}

int ed448_verify(const uint8_t *public_key,  size_t pub_len,
                 const uint8_t *msg,          size_t msg_len,
                 const uint8_t *sig,          size_t sig_len,
                 const uint8_t *context,      uint8_t context_len)
{
    if (!public_key || (!msg && msg_len) || !sig) return -1;
    if (pub_len != ED448_PUBLIC_KEY_SIZE || sig_len != ED448_SIGNATURE_SIZE) return -1;

    ed448_key key;
    if (wc_ed448_init(&key) != 0) return -1;

    int ret = -1, res = 0;
    if (wc_ed448_import_public(public_key, (word32)pub_len, &key) != 0) goto done;
    if (wc_ed448_verify_msg(sig, (word32)sig_len, msg, (word32)msg_len,
                            &res, &key, context, context_len) != 0) goto done;
    ret = (res == 1) ? 0 : -1;
done:
    wc_ed448_free(&key);
    return ret;
}

int ed448ph_sign(const uint8_t *private_key, size_t priv_len,
                 const uint8_t *public_key,  size_t pub_len,
                 const uint8_t  hash[64],
                 const uint8_t *context,     uint8_t context_len,
                 uint8_t        sig[ED448_SIGNATURE_SIZE])
{
    if (!private_key || !public_key || !hash || !sig) return -1;
    if (priv_len != ED448_PRIVATE_KEY_SIZE || pub_len != ED448_PUBLIC_KEY_SIZE) return -1;

    ed448_key key;
    if (wc_ed448_init(&key) != 0) return -1;

    int ret = -1;
    if (wc_ed448_import_private_key(private_key, priv_len,
                                     public_key,  pub_len, &key) != 0) goto done;
    word32 sig_sz = ED448_SIGNATURE_SIZE;
    if (wc_ed448ph_sign_hash(hash, 64, sig, &sig_sz, &key,
                              context, context_len) != 0) goto done;
    ret = 0;
done:
    wc_ed448_free(&key);
    return ret;
}

int ed448ph_verify(const uint8_t *public_key,  size_t pub_len,
                   const uint8_t  hash[64],
                   const uint8_t *sig,          size_t sig_len,
                   const uint8_t *context,      uint8_t context_len)
{
    if (!public_key || !hash || !sig) return -1;
    if (pub_len != ED448_PUBLIC_KEY_SIZE || sig_len != ED448_SIGNATURE_SIZE) return -1;

    ed448_key key;
    if (wc_ed448_init(&key) != 0) return -1;

    int ret = -1, res = 0;
    if (wc_ed448_import_public(public_key, (word32)pub_len, &key) != 0) goto done;
    if (wc_ed448ph_verify_hash(sig, (word32)sig_len, hash, 64,
                               &res, &key, context, context_len) != 0) goto done;
    ret = (res == 1) ? 0 : -1;
done:
    wc_ed448_free(&key);
    return ret;
}
