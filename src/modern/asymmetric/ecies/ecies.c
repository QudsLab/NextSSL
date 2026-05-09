/* ecies.c — ECIES-P256-SHA256-AES128GCM (SEC1v2 §5.1) */
#include "ecies.h"
#include "../p256/p256.h"
#include "../../aead/aes_gcm/aes_gcm.h"
#include "../../kdf/hkdf/hkdf.h"
#include <string.h>

extern int rng_fill(void *buf, size_t len);

/* KDF: HKDF-SHA256 with fixed info to derive enc_key and mac_key */
static int ecies_kdf(const uint8_t Z[32], const uint8_t *ephem_pub, size_t pub_len,
                     uint8_t enc_key[16], uint8_t nonce[12])
{
    uint8_t okm[28]; /* 16 (enc_key) + 12 (nonce) */
    int ret = hkdf_ex(NULL /* SHA-256 */, ephem_pub, pub_len,
                      Z, 32,
                      (const uint8_t *)"ECIES-P256-AES128GCM", 20,
                      okm, 28);
    if (ret != 0) return -1;
    memcpy(enc_key, okm,      16);
    memcpy(nonce,   okm + 16, 12);
    return 0;
}

int ecies_encrypt(const uint8_t  recipient_pub[64],
                  const uint8_t *plaintext, size_t pt_len,
                  uint8_t       *ciphertext, size_t *ct_len)
{
    if (!recipient_pub || (!plaintext && pt_len) || !ciphertext || !ct_len) return -1;
    if (*ct_len < pt_len + ECIES_OVERHEAD) return -1;

    /* 1. Generate ephemeral key pair */
    uint8_t R_priv[32], R_pub[64];
    if (p256_keygen(R_priv, R_pub) != 0) return -1;

    /* 2. Z = ECDH(R_priv, recipient_pub) */
    uint8_t Z[32];
    if (p256_ecdh(recipient_pub, R_priv, Z) != 0) {
        memset(R_priv, 0, 32);
        return -1;
    }

    /* 3. Derive keys: enc_key (16), nonce (12) */
    uint8_t enc_key[16], nonce[12];
    if (ecies_kdf(Z, R_pub, 64, enc_key, nonce) != 0) {
        memset(R_priv, 0, 32); memset(Z, 0, 32);
        return -1;
    }

    /* 4. Layout: [ R_pub(64) | nonce(12) | ct(pt_len) | tag(16) ] */
    uint8_t *p = ciphertext;
    memcpy(p, R_pub, 64);  p += 64;
    memcpy(p, nonce, 12);  p += 12;

    /* AES-128-GCM encrypt */
    size_t tag_out = 16;
    int ret = aes_gcm_encrypt(enc_key, 128, nonce, 12,
                               NULL, 0,
                               plaintext, pt_len,
                               p, p + pt_len, &tag_out);

    memset(R_priv, 0, 32); memset(Z, 0, 32); memset(enc_key, 0, 16);

    if (ret != 0) return -1;
    *ct_len = ECIES_EPHEMERAL_PUB_SIZE + ECIES_NONCE_SIZE + pt_len + ECIES_TAG_SIZE;
    return 0;
}

int ecies_decrypt(const uint8_t  recipient_priv[32],
                  const uint8_t *ciphertext, size_t ct_len,
                  uint8_t       *plaintext,  size_t *pt_len)
{
    if (!recipient_priv || !ciphertext || !plaintext || !pt_len) return -1;
    if (ct_len < ECIES_OVERHEAD) return -1;

    size_t msg_len = ct_len - ECIES_OVERHEAD;
    if (*pt_len < msg_len) return -1;

    const uint8_t *R_pub  = ciphertext;                               /* 64 bytes */
    const uint8_t *nonce  = ciphertext + ECIES_EPHEMERAL_PUB_SIZE;   /* 12 bytes */
    const uint8_t *ct     = nonce + ECIES_NONCE_SIZE;                 /* msg_len bytes */
    const uint8_t *tag    = ct + msg_len;                             /* 16 bytes */

    /* 1. Z = ECDH(recipient_priv, R_pub) */
    uint8_t Z[32];
    if (p256_ecdh(R_pub, recipient_priv, Z) != 0) return -1;

    /* 2. Re-derive keys */
    uint8_t enc_key[16], derived_nonce[12];
    if (ecies_kdf(Z, R_pub, 64, enc_key, derived_nonce) != 0) {
        memset(Z, 0, 32);
        return -1;
    }

    /* Sanity: derived nonce should match the stored nonce */
    if (memcmp(derived_nonce, nonce, 12) != 0) {
        memset(Z, 0, 32); memset(enc_key, 0, 16);
        return -1;
    }

    /* 3. AES-128-GCM decrypt and authenticate */
    int ret = aes_gcm_decrypt(enc_key, 128, nonce, 12,
                               NULL, 0,
                               ct, msg_len,
                               tag, 16,
                               plaintext);

    memset(Z, 0, 32); memset(enc_key, 0, 16);
    if (ret != 0) return -1;
    *pt_len = msg_len;
    return 0;
}
