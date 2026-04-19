/* root_modern.c — Modern Cryptography API Implementation (Plan 405)
 *
 * Thin export layer over src/modern/.
 */
#include "root_modern.h"
#include "../seed/root_seed.h"
#include "../../modern/symmetric/aes_cbc.h"
#include "../../modern/symmetric/aes_ecb.h"
#include "../../modern/symmetric/aes_ctr.h"
#include "../../modern/symmetric/aes_cfb.h"
#include "../../modern/symmetric/aes_ofb.h"
#include "../../modern/symmetric/aes_xts.h"
#include "../../modern/symmetric/aes_fpe.h"
#include "../../modern/symmetric/aes_kw.h"
#include "../../modern/symmetric/three_des.h"
#include "../../modern/aead/aes_gcm.h"
#include "../../modern/aead/aes_ccm.h"
#include "../../modern/aead/aes_eax.h"
#include "../../modern/aead/aes_gcm_siv.h"
#include "../../modern/aead/aes_ocb.h"
#include "../../modern/aead/aes_siv.h"
#include "../../modern/aead/chacha20_poly1305.h"
#include "../../modern/symmetric/chacha20.h"
#include "../../modern/mac/hmac.h"
#include "../../modern/mac/poly1305.h"
#include "../../modern/mac/aes_cmac.h"
#include "../../modern/mac/siphash.h"
#include "../../modern/kdf/hkdf.h"
#include "../../modern/kdf/pbkdf2.h"
#include "../../modern/aead/monocypher.h"
#include "../../modern/asymmetric/ed25519.h"
#include "../../modern/asymmetric/p256.h"
#include "../../modern/asymmetric/p384.h"
#include "../../modern/asymmetric/p521.h"
#include "../../common/secure_zero.h"
#include "../../hash/interface/hash_registry.h"
#include "../../seed/random/seed_derive_random.h"
#include <string.h>

static int modern_join_label(const char *prefix,
                             const char *suffix,
                             char out[257])
{
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = (suffix && suffix[0] != '\0') ? strlen(suffix) : 0;

    if (prefix_len + suffix_len > 256) return -1;

    memcpy(out, prefix, prefix_len);
    if (suffix_len > 0) memcpy(out + prefix_len, suffix, suffix_len);
    out[prefix_len + suffix_len] = '\0';
    return 0;
}

static int modern_random_bytes(const char *label, uint8_t *out, size_t out_len)
{
    return seed_derive_random_label(label, out, out_len);
}

static int modern_derive_bytes(const char *algo,
                               const char *label,
                               const uint8_t *seed,
                               size_t seed_len,
                               uint8_t *out,
                               size_t out_len)
{
    if (!seed || seed_len == 0) return -1;
    return nextssl_seed_derive(algo, label, seed, seed_len, out, out_len);
}

static void x25519_clamp_private(uint8_t sk[32])
{
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

/* =========================================================================
 * Symmetric — AES-CBC
 * =========================================================================*/
int nextssl_sym_aes_cbc_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out)
{
    (void)key_len;  /* AES_CBC_encrypt uses key directly; key_len is inferred */
    return AES_CBC_encrypt(key, iv, in, in_len, out) == 0 ? 0 : -1;
}

int nextssl_sym_aes_cbc_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out)
{
    (void)key_len;
    return AES_CBC_decrypt(key, iv, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — AES-GCM
 * =========================================================================*/
void nextssl_aead_aes_gcm_encrypt(
    const uint8_t *key,   size_t key_len,
    const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out)
{
    (void)key_len;
    AES_GCM_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_aes_gcm_decrypt(
    const uint8_t *key,   size_t key_len,
    const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out)
{
    (void)key_len;
    return AES_GCM_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * Symmetric — ChaCha20 (IETF)
 * =========================================================================*/
int nextssl_sym_chacha20(
    const uint8_t *key,
    const uint8_t  nonce[12],
    uint32_t       counter,
    const uint8_t *in, size_t in_len,
    uint8_t       *out)
{
    if (!key || !nonce || !in || !out) return -1;
    chacha20_ietf(out, in, in_len, key, nonce, counter);
    return 0;
}

/* =========================================================================
 * MAC — HMAC
 * =========================================================================*/
int nextssl_mac_hmac(
    const char    *algo,
    const uint8_t *key,  size_t key_len,
    const uint8_t *msg,  size_t msg_len,
    uint8_t       *out,  size_t *out_len)
{
    const hash_ops_t *ops;

    if (!algo || !out || !out_len) return -1;

    hash_registry_init();
    ops = hash_lookup(algo);
    if (!ops) return -1;

    if (*out_len < ops->digest_size) return -1;

    int rc = hmac_compute(ops, key, key_len, msg, msg_len, out);
    if (rc == 0) *out_len = ops->digest_size;
    return rc;
}

/* =========================================================================
 * MAC — Poly1305
 * =========================================================================*/
int nextssl_mac_poly1305(
    const uint8_t  key[32],
    const uint8_t *msg, size_t msg_len,
    uint8_t        out[16])
{
    if (!key || !msg || !out) return -1;
    poly1305(out, msg, msg_len, key);
    return 0;
}

/* =========================================================================
 * KDF — HKDF
 * =========================================================================*/
int nextssl_kdf_hkdf(
    const char    *algo,
    const uint8_t *salt,  size_t salt_len,
    const uint8_t *ikm,   size_t ikm_len,
    const uint8_t *info,  size_t info_len,
    uint8_t       *out,   size_t out_len)
{
    const hash_ops_t *ops = NULL;

    if (algo && algo[0] != '\0') {
        hash_registry_init();
        ops = hash_lookup(algo);
        if (!ops) return -1;
    }
    /* NULL ops → hkdf_ex defaults to sha256 */
    return hkdf_ex(ops, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len);
}

/* =========================================================================
 * KDF — PBKDF2
 * =========================================================================*/
int nextssl_kdf_pbkdf2(
    const char    *algo,
    const uint8_t *pass,  size_t pass_len,
    const uint8_t *salt,  size_t salt_len,
    uint32_t       iterations,
    uint8_t       *out,   size_t out_len)
{
    const hash_ops_t *ops = NULL;

    if (algo && algo[0] != '\0') {
        hash_registry_init();
        ops = hash_lookup(algo);
        if (!ops) return -1;
    }
    return pbkdf2_ex(ops, pass, pass_len, salt, salt_len, iterations, out, out_len);
}

int nextssl_modern_seed_key(
    const char    *algo,
    const char    *label,
    const uint8_t *seed,  size_t seed_len,
    uint8_t       *out,   size_t out_len)
{
    char domain[257];
    if (modern_join_label("modern:key:", label, domain) != 0) return -1;
    return modern_derive_bytes(algo, domain, seed, seed_len, out, out_len);
}

int nextssl_modern_seed_nonce(
    const char    *algo,
    const char    *label,
    const uint8_t *seed,  size_t seed_len,
    uint8_t       *out,   size_t out_len)
{
    char domain[257];
    if (modern_join_label("modern:nonce:", label, domain) != 0) return -1;
    return modern_derive_bytes(algo, domain, seed, seed_len, out, out_len);
}

/* =========================================================================
 * Asymmetric — Ed25519
 * =========================================================================*/
int nextssl_asym_ed25519_keypair(uint8_t *pk, uint8_t *sk)
{
    unsigned char seed[32];
    if (!pk || !sk) return -1;
    if (modern_random_bytes("modern:ed25519:keypair", seed, sizeof(seed)) != 0) return -1;
    ed25519_create_keypair(pk, sk, seed);
    secure_zero(seed, sizeof(seed));
    return 0;
}

int nextssl_asym_ed25519_keypair_derand(
    uint8_t       *pk,
    uint8_t       *sk,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    uint8_t material[32];
    if (!pk || !sk) return -1;
    if (modern_derive_bytes(algo, "modern:ed25519:keypair", seed, seed_len,
                            material, sizeof(material)) != 0) return -1;
    ed25519_create_keypair(pk, sk, material);
    secure_zero(material, sizeof(material));
    return 0;
}

int nextssl_asym_ed25519_sign(
    uint8_t       *sig,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk,
    const uint8_t *sk)
{
    if (!sig || !msg || !pk || !sk) return -1;
    ed25519_sign(sig, msg, msg_len, pk, sk);
    return 0;
}

int nextssl_asym_ed25519_verify(
    const uint8_t *sig,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk)
{
    if (!sig || !msg || !pk) return -1;
    return ed25519_verify(sig, msg, msg_len, pk);  /* 1 = valid, 0 = invalid */
}

/* =========================================================================
 * Asymmetric — X25519 (key exchange via ed25519 key_exchange)
 * =========================================================================*/
int nextssl_asym_x25519_keypair(uint8_t *pk, uint8_t *sk)
{
    unsigned char material[32];
    if (!pk || !sk) return -1;
    if (modern_random_bytes("modern:x25519:keypair", material, sizeof(material)) != 0) return -1;
    memcpy(sk, material, sizeof(material));
    x25519_clamp_private(sk);
    crypto_x25519_public_key(pk, sk);
    secure_zero(material, sizeof(material));
    return 0;
}

int nextssl_asym_x25519_keypair_derand(
    uint8_t       *pk,
    uint8_t       *sk,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    uint8_t material[32];
    if (!pk || !sk) return -1;
    if (modern_derive_bytes(algo, "modern:x25519:keypair", seed, seed_len,
                            material, sizeof(material)) != 0) return -1;
    memcpy(sk, material, sizeof(material));
    x25519_clamp_private(sk);
    crypto_x25519_public_key(pk, sk);
    secure_zero(material, sizeof(material));
    return 0;
}

int nextssl_asym_x25519_exchange(
    uint8_t       *shared,
    const uint8_t *sk,
    const uint8_t *their_pk)
{
    if (!shared || !sk || !their_pk) return -1;
    crypto_x25519(shared, sk, their_pk);
    return 0;
}

/* =========================================================================
 * Asymmetric — P-256, P-384, P-521 (stub implementations)
 * =========================================================================*/
int nextssl_asym_p256_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[32];
    int rc;
    if (!pk || !sk) return -1;
    if (modern_random_bytes("modern:p256:keypair", seed, sizeof(seed)) != 0) return -1;
    rc = p256_keygen_from_seed(seed, sizeof(seed), sk, pk);
    secure_zero(seed, sizeof(seed));
    return rc;
}

int nextssl_asym_p256_keypair_derand(
    uint8_t       *pk,
    uint8_t       *sk,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    uint8_t material[32];
    int rc;
    if (!pk || !sk) return -1;
    if (modern_derive_bytes(algo, "modern:p256:keypair", seed, seed_len,
                            material, sizeof(material)) != 0) return -1;
    rc = p256_keygen_from_seed(material, sizeof(material), sk, pk);
    secure_zero(material, sizeof(material));
    return rc;
}

int nextssl_asym_p256_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared)
{
    return p256_ecdh(their_pk, our_sk, shared);
}

int nextssl_asym_p384_keypair(uint8_t *pk, uint8_t *sk)
{
    return p384_keygen(sk, pk);
}

int nextssl_asym_p384_keypair_derand(
    uint8_t       *pk,
    uint8_t       *sk,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    (void)pk;
    (void)sk;
    (void)algo;
    (void)seed;
    (void)seed_len;
    return -1;
}

int nextssl_asym_p384_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared)
{
    return p384_ecdh(their_pk, our_sk, shared);
}

int nextssl_asym_p521_keypair(uint8_t *pk, uint8_t *sk)
{
    return p521_keygen(sk, pk);
}

int nextssl_asym_p521_keypair_derand(
    uint8_t       *pk,
    uint8_t       *sk,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    (void)pk;
    (void)sk;
    (void)algo;
    (void)seed;
    (void)seed_len;
    return -1;
}

int nextssl_asym_p521_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared)
{
    return p521_ecdh(their_pk, our_sk, shared);
}

/* =========================================================================
 * Symmetric — AES-ECB
 * =========================================================================*/
int nextssl_sym_aes_ecb_encrypt(
    const uint8_t *key,
    const uint8_t *in, size_t in_len,
    uint8_t       *out)
{
    if (!key || !in || !out) return -1;
    AES_ECB_encrypt(key, in, in_len, out);
    return 0;
}

int nextssl_sym_aes_ecb_decrypt(
    const uint8_t *key,
    const uint8_t *in, size_t in_len,
    uint8_t       *out)
{
    if (!key || !in || !out) return -1;
    return AES_ECB_decrypt(key, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * Symmetric — AES-CTR
 * =========================================================================*/
int nextssl_sym_aes_ctr_encrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_CTR_encrypt(key, iv, in, in_len, out);
    return 0;
}

int nextssl_sym_aes_ctr_decrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_CTR_decrypt(key, iv, in, in_len, out);
    return 0;
}

/* =========================================================================
 * Symmetric — AES-CFB
 * =========================================================================*/
int nextssl_sym_aes_cfb_encrypt(
    const uint8_t *key, const uint8_t iv[16],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_CFB_encrypt(key, iv, in, in_len, out);
    return 0;
}

int nextssl_sym_aes_cfb_decrypt(
    const uint8_t *key, const uint8_t iv[16],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_CFB_decrypt(key, iv, in, in_len, out);
    return 0;
}

/* =========================================================================
 * Symmetric — AES-OFB
 * =========================================================================*/
int nextssl_sym_aes_ofb_encrypt(
    const uint8_t *key, const uint8_t iv[16],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_OFB_encrypt(key, iv, in, in_len, out);
    return 0;
}

int nextssl_sym_aes_ofb_decrypt(
    const uint8_t *key, const uint8_t iv[16],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    AES_OFB_decrypt(key, iv, in, in_len, out);
    return 0;
}

/* =========================================================================
 * Symmetric — AES-XTS
 * =========================================================================*/
int nextssl_sym_aes_xts_encrypt(
    const uint8_t *keys, const uint8_t *tweak,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!keys || !tweak || !in || !out) return -1;
    return AES_XTS_encrypt(keys, tweak, in, in_len, out) == 0 ? 0 : -1;
}

int nextssl_sym_aes_xts_decrypt(
    const uint8_t *keys, const uint8_t *tweak,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!keys || !tweak || !in || !out) return -1;
    return AES_XTS_decrypt(keys, tweak, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * Symmetric — AES-FPE (FF1)
 * =========================================================================*/
int nextssl_sym_aes_fpe_encrypt(
    const uint8_t *key,
    uint8_t *tweak, size_t tweak_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !in || !out) return -1;
    return AES_FPE_encrypt(key, tweak, tweak_len, in, in_len, out) == 0 ? 0 : -1;
}

int nextssl_sym_aes_fpe_decrypt(
    const uint8_t *key,
    uint8_t *tweak, size_t tweak_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !in || !out) return -1;
    return AES_FPE_decrypt(key, tweak, tweak_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * Symmetric — AES Key Wrap
 * =========================================================================*/
int nextssl_sym_aes_kw_wrap(
    const uint8_t *kek,
    const uint8_t *secret, size_t secret_len,
    uint8_t *wrapped)
{
    if (!kek || !secret || !wrapped) return -1;
    return AES_KEY_wrap(kek, secret, secret_len, wrapped) == 0 ? 0 : -1;
}

int nextssl_sym_aes_kw_unwrap(
    const uint8_t *kek,
    const uint8_t *wrapped, size_t wrap_len,
    uint8_t *secret)
{
    if (!kek || !wrapped || !secret) return -1;
    return AES_KEY_unwrap(kek, wrapped, wrap_len, secret) == 0 ? 0 : -1;
}

/* =========================================================================
 * Symmetric — 3DES-CBC
 * =========================================================================*/
int nextssl_sym_3des_cbc_encrypt(
    const uint8_t key[24], const uint8_t iv[8],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    return three_des_cbc_encrypt(key, iv, in, in_len, out);
}

int nextssl_sym_3des_cbc_decrypt(
    const uint8_t key[24], const uint8_t iv[8],
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    if (!key || !iv || !in || !out) return -1;
    return three_des_cbc_decrypt(key, iv, in, in_len, out);
}

/* =========================================================================
 * AEAD — AES-CCM
 * =========================================================================*/
void nextssl_aead_aes_ccm_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    AES_CCM_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_aes_ccm_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return AES_CCM_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — AES-EAX
 * =========================================================================*/
void nextssl_aead_aes_eax_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    AES_EAX_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_aes_eax_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return AES_EAX_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — AES-GCM-SIV
 * =========================================================================*/
void nextssl_aead_aes_gcm_siv_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    GCM_SIV_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_aes_gcm_siv_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return GCM_SIV_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — AES-OCB
 * =========================================================================*/
void nextssl_aead_aes_ocb_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    AES_OCB_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_aes_ocb_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return AES_OCB_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — AES-SIV
 * =========================================================================*/
void nextssl_aead_aes_siv_encrypt(
    const uint8_t *keys,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t iv[16], uint8_t *out)
{
    AES_SIV_encrypt(keys, aad, aad_len, in, in_len, iv, out);
}

int nextssl_aead_aes_siv_decrypt(
    const uint8_t *keys, const uint8_t iv[16],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return AES_SIV_decrypt(keys, iv, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * AEAD — ChaCha20-Poly1305
 * =========================================================================*/
void nextssl_aead_chacha20_poly1305_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    ChaCha20_Poly1305_encrypt(key, nonce, aad, aad_len, in, in_len, out);
}

int nextssl_aead_chacha20_poly1305_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, uint8_t *out)
{
    return ChaCha20_Poly1305_decrypt(key, nonce, aad, aad_len, in, in_len, out) == 0 ? 0 : -1;
}

/* =========================================================================
 * MAC — AES-CMAC
 * =========================================================================*/
int nextssl_mac_aes_cmac(
    const uint8_t *key,
    const uint8_t *data, size_t data_len,
    uint8_t mac[16])
{
    if (!key || !data || !mac) return -1;
    AES_CMAC(key, data, data_len, mac);
    return 0;
}

/* =========================================================================
 * MAC — SipHash
 * =========================================================================*/
int nextssl_mac_siphash(
    const uint8_t key[16],
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t out_len)
{
    if (!key || !out) return -1;
    return siphash(in, in_len, key, out, out_len);
}

/* =========================================================================
 * Asymmetric — Ed448
 * =========================================================================*/
#ifdef HAVE_ED448
#include "../../modern/asymmetric/ed448.h"

static int ed448_keypair_from_bytes(uint8_t pk[57], uint8_t sk[57])
{
    ed448_key key;

    if (wc_ed448_init(&key) != 0) return -1;
    if (wc_ed448_import_private_only(sk, 57, &key) != 0) {
        wc_ed448_free(&key);
        return -1;
    }
    if (wc_ed448_make_public(&key, pk, 57) != 0) {
        wc_ed448_free(&key);
        return -1;
    }
    wc_ed448_free(&key);
    return 0;
}

int nextssl_asym_ed448_keypair(uint8_t pk[57], uint8_t sk[57])
{
    if (!pk || !sk) return -1;
    if (modern_random_bytes("modern:ed448:keypair", sk, 57) != 0) return -1;
    return ed448_keypair_from_bytes(pk, sk);
}

int nextssl_asym_ed448_keypair_derand(
    uint8_t        pk[57],
    uint8_t        sk[57],
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    if (!pk || !sk) return -1;
    if (modern_derive_bytes(algo, "modern:ed448:keypair", seed, seed_len,
                            sk, 57) != 0) return -1;
    return ed448_keypair_from_bytes(pk, sk);
}

int nextssl_asym_ed448_sign(
    uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t sk[57],
    const uint8_t *ctx, size_t ctx_len)
{
    ed448_key key;
    if (!sig || !sig_len || !msg || !sk) return -1;
    if (wc_ed448_init(&key) != 0) return -1;
    if (wc_ed448_import_private_only(sk, 57, &key) != 0) { wc_ed448_free(&key); return -1; }
    word32 sl = (word32)*sig_len;
    int rc = wc_ed448_sign_msg(msg, (word32)msg_len, sig, &sl, &key, ctx, (byte)(ctx_len & 0xFF));
    *sig_len = sl;
    wc_ed448_free(&key);
    return rc == 0 ? 0 : -1;
}

int nextssl_asym_ed448_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t pk[57],
    const uint8_t *ctx, size_t ctx_len)
{
    ed448_key key;
    int res = 0;
    if (!sig || !msg || !pk) return -1;
    if (wc_ed448_init(&key) != 0) return -1;
    if (wc_ed448_import_public(pk, 57, &key) != 0) { wc_ed448_free(&key); return -1; }
    int rc = wc_ed448_verify_msg(sig, (word32)sig_len, msg, (word32)msg_len, &res, &key, ctx, (byte)(ctx_len & 0xFF));
    wc_ed448_free(&key);
    return (rc == 0 && res == 1) ? 1 : 0;
}
#else
int nextssl_asym_ed448_keypair(uint8_t pk[57], uint8_t sk[57])
{
    (void)pk;
    (void)sk;
    return -1;
}

int nextssl_asym_ed448_keypair_derand(
    uint8_t        pk[57],
    uint8_t        sk[57],
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    (void)pk;
    (void)sk;
    (void)algo;
    (void)seed;
    (void)seed_len;
    return -1;
}

int nextssl_asym_ed448_sign(
    uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t sk[57],
    const uint8_t *ctx, size_t ctx_len)
{
    (void)sig;
    (void)sig_len;
    (void)msg;
    (void)msg_len;
    (void)sk;
    (void)ctx;
    (void)ctx_len;
    return -1;
}

int nextssl_asym_ed448_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t pk[57],
    const uint8_t *ctx, size_t ctx_len)
{
    (void)sig;
    (void)sig_len;
    (void)msg;
    (void)msg_len;
    (void)pk;
    (void)ctx;
    (void)ctx_len;
    return -1;
}
#endif

/* =========================================================================
 * Asymmetric — X448 / Curve448
 * =========================================================================*/
#ifdef HAVE_CURVE448
#include "../../modern/asymmetric/curve448.h"
#include "../../modern/asymmetric/curve448_det.h"

int nextssl_asym_x448_keypair(uint8_t pk[56], uint8_t sk[56])
{
    curve448_key key;
    if (!pk || !sk) return -1;
    if (wc_curve448_init(&key) != 0) return -1;
    if (modern_random_bytes("modern:x448:keypair", sk, 56) != 0) {
        wc_curve448_free(&key);
        return -1;
    }
    if (wc_curve448_make_key_deterministic(&key, sk, 56) != 0) { wc_curve448_free(&key); return -1; }
    word32 pk_len = 56, sk_len = 56;
    int rc = wc_curve448_export_key_raw(&key, sk, &sk_len, pk, &pk_len);
    wc_curve448_free(&key);
    return rc == 0 ? 0 : -1;
}

int nextssl_asym_x448_keypair_derand(
    uint8_t        pk[56],
    uint8_t        sk[56],
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    curve448_key key;
    if (!pk || !sk) return -1;
    if (modern_derive_bytes(algo, "modern:x448:keypair", seed, seed_len,
                            sk, 56) != 0) return -1;
    if (wc_curve448_init(&key) != 0) return -1;
    if (wc_curve448_make_key_deterministic(&key, sk, 56) != 0) {
        wc_curve448_free(&key);
        return -1;
    }
    word32 pk_len = 56, sk_len = 56;
    int rc = wc_curve448_export_key_raw(&key, sk, &sk_len, pk, &pk_len);
    wc_curve448_free(&key);
    return rc == 0 ? 0 : -1;
}

int nextssl_asym_x448_exchange(
    uint8_t *shared,
    const uint8_t sk[56],
    const uint8_t their_pk[56])
{
    curve448_key priv, pub;
    if (!shared || !sk || !their_pk) return -1;
    if (wc_curve448_init(&priv) != 0) return -1;
    if (wc_curve448_init(&pub) != 0) { wc_curve448_free(&priv); return -1; }
    if (wc_curve448_import_private(sk, 56, &priv) != 0) goto fail;
    if (wc_curve448_import_public(their_pk, 56, &pub) != 0) goto fail;
    word32 out_len = 56;
    int rc = wc_curve448_shared_secret(&priv, &pub, shared, &out_len);
    wc_curve448_free(&pub);
    wc_curve448_free(&priv);
    return rc == 0 ? 0 : -1;
fail:
    wc_curve448_free(&pub);
    wc_curve448_free(&priv);
    return -1;
}
#else
int nextssl_asym_x448_keypair(uint8_t pk[56], uint8_t sk[56])
{
    (void)pk;
    (void)sk;
    return -1;
}

int nextssl_asym_x448_keypair_derand(
    uint8_t        pk[56],
    uint8_t        sk[56],
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    (void)pk;
    (void)sk;
    (void)algo;
    (void)seed;
    (void)seed_len;
    return -1;
}

int nextssl_asym_x448_exchange(
    uint8_t *shared,
    const uint8_t sk[56],
    const uint8_t their_pk[56])
{
    (void)shared;
    (void)sk;
    (void)their_pk;
    return -1;
}
#endif

/* =========================================================================
 * Asymmetric — RSA
 * =========================================================================*/
#include "../../modern/asymmetric/rsa/rsa.h"

#ifdef NEXTSSL_HAS_BEARSSL
void *nextssl_asym_rsa_alloc(void)   { return rsa_keypair_alloc(); }
void  nextssl_asym_rsa_free(void *kp) { rsa_keypair_free(kp); }

int nextssl_asym_rsa_keygen(void *kp, unsigned bits)
{
    uint8_t seed[64];
    int rc;
    if (!kp) return -1;
    if (modern_random_bytes("modern:rsa:keygen", seed, sizeof(seed)) != 0) return -1;
    rc = rsa_keygen_seeded(kp, bits, seed, sizeof(seed));
    secure_zero(seed, sizeof(seed));
    return rc == 0 ? 0 : -1;
}

int nextssl_asym_rsa_keygen_derand(
    void          *kp,
    unsigned       bits,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    uint8_t material[64];
    int rc;
    if (!kp) return -1;
    if (modern_derive_bytes(algo, "modern:rsa:keygen", seed, seed_len,
                            material, sizeof(material)) != 0) return -1;
    rc = rsa_keygen_seeded(kp, bits, material, sizeof(material));
    secure_zero(material, sizeof(material));
    return rc == 0 ? 0 : -1;
}

int nextssl_asym_rsa_pkcs1_sign(
    const void *kp, const uint8_t *hash, size_t hash_len,
    uint8_t *sig, size_t *sig_len)
{
    if (!kp || !hash || !sig || !sig_len) return -1;
    return rsa_pkcs1_sign(kp, NULL, hash, hash_len, sig, sig_len) ? 0 : -1;
}

int nextssl_asym_rsa_pkcs1_verify(
    const void *pk, const uint8_t *hash, size_t hash_len,
    const uint8_t *sig, size_t sig_len)
{
    if (!pk || !hash || !sig) return -1;
    return rsa_pkcs1_verify(pk, NULL, hash, hash_len, sig, sig_len) ? 1 : 0;
}

int nextssl_asym_rsa_oaep_encrypt(
    const void *pk, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    if (!pk || !in || !out || !out_len) return -1;
    return rsa_oaep_encrypt(pk, NULL, NULL, 0, in, in_len, out, out_len) ? 0 : -1;
}

int nextssl_asym_rsa_oaep_decrypt(
    const void *kp, uint8_t *data, size_t *data_len)
{
    if (!kp || !data || !data_len) return -1;
    return rsa_oaep_decrypt(kp, NULL, NULL, 0, data, data_len) ? 0 : -1;
}
#else
void *nextssl_asym_rsa_alloc(void)   { return NULL; }
void  nextssl_asym_rsa_free(void *kp) { (void)kp; }

int nextssl_asym_rsa_keygen(void *kp, unsigned bits)
{
    (void)kp;
    (void)bits;
    return -1;
}

int nextssl_asym_rsa_keygen_derand(
    void          *kp,
    unsigned       bits,
    const char    *algo,
    const uint8_t *seed,
    size_t         seed_len)
{
    (void)kp;
    (void)bits;
    (void)algo;
    (void)seed;
    (void)seed_len;
    return -1;
}

int nextssl_asym_rsa_pkcs1_sign(
    const void *kp, const uint8_t *hash, size_t hash_len,
    uint8_t *sig, size_t *sig_len)
{
    (void)kp;
    (void)hash;
    (void)hash_len;
    (void)sig;
    (void)sig_len;
    return -1;
}

int nextssl_asym_rsa_pkcs1_verify(
    const void *pk, const uint8_t *hash, size_t hash_len,
    const uint8_t *sig, size_t sig_len)
{
    (void)pk;
    (void)hash;
    (void)hash_len;
    (void)sig;
    (void)sig_len;
    return -1;
}

int nextssl_asym_rsa_oaep_encrypt(
    const void *pk, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    (void)pk;
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_len;
    return -1;
}

int nextssl_asym_rsa_oaep_decrypt(
    const void *kp, uint8_t *data, size_t *data_len)
{
    (void)kp;
    (void)data;
    (void)data_len;
    return -1;
}
#endif /* NEXTSSL_HAS_BEARSSL */

/* =========================================================================
 * Asymmetric — SM2
 * =========================================================================*/
#ifdef NEXTSSL_HAS_GMSSL
#include "../../modern/asymmetric/sm2/sm2.h"

int nextssl_asym_sm2_sign(
    const void *key, const uint8_t dgst[32],
    uint8_t *sig, size_t *sig_len)
{
    if (!key || !dgst || !sig || !sig_len) return -1;
    return sm2_sign_der(key, dgst, sig, sig_len);
}

int nextssl_asym_sm2_verify(
    const void *key, const uint8_t dgst[32],
    const uint8_t *sig, size_t sig_len)
{
    if (!key || !dgst || !sig) return -1;
    return sm2_verify_der(key, dgst, sig, sig_len);
}

int nextssl_asym_sm2_encrypt(
    const void *key, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    if (!key || !in || !out || !out_len) return -1;
    return sm2_enc(key, in, in_len, out, out_len);
}

int nextssl_asym_sm2_decrypt(
    const void *key, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    if (!key || !in || !out || !out_len) return -1;
    return sm2_dec(key, in, in_len, out, out_len);
}
#else
int nextssl_asym_sm2_sign(
    const void *key, const uint8_t dgst[32],
    uint8_t *sig, size_t *sig_len)
{
    (void)key;
    (void)dgst;
    (void)sig;
    (void)sig_len;
    return -1;
}

int nextssl_asym_sm2_verify(
    const void *key, const uint8_t dgst[32],
    const uint8_t *sig, size_t sig_len)
{
    (void)key;
    (void)dgst;
    (void)sig;
    (void)sig_len;
    return -1;
}

int nextssl_asym_sm2_encrypt(
    const void *key, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    (void)key;
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_len;
    return -1;
}

int nextssl_asym_sm2_decrypt(
    const void *key, const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len)
{
    (void)key;
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_len;
    return -1;
}
#endif

/* =========================================================================
 * Encoding — Base58Check
 * =========================================================================*/
#include "../../modern/encoding/base58check.h"

int nextssl_enc_base58check_encode(
    uint8_t version, const uint8_t *payload, size_t payload_len,
    char *dst, size_t dst_cap, size_t *out_len)
{
    return base58check_encode(version, payload, payload_len, dst, dst_cap, out_len);
}

int nextssl_enc_base58check_decode(
    const char *src, size_t src_len,
    uint8_t *version_out, uint8_t *payload, size_t payload_cap,
    size_t *payload_len)
{
    return base58check_decode(src, src_len, version_out, payload, payload_cap, payload_len);
}

/* =========================================================================
 * Encoding — Base62
 * =========================================================================*/
#include "../../modern/encoding/base62.h"

int nextssl_enc_base62_encode(const uint8_t *src, size_t src_len,
    char *dst, size_t dst_cap, size_t *out_len)
{
    return base62_encode(src, src_len, dst, dst_cap, out_len);
}

int nextssl_enc_base62_decode(const char *src, size_t src_len,
    uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    return base62_decode(src, src_len, dst, dst_cap, out_len);
}

/* =========================================================================
 * Encoding — Base85
 * =========================================================================*/
#include "../../modern/encoding/base85.h"

int nextssl_enc_base85_encode(const uint8_t *src, size_t src_len,
    char *dst, size_t dst_cap, size_t *out_len)
{
    return base85_encode(src, src_len, dst, dst_cap, out_len);
}

int nextssl_enc_base85_decode(const char *src, size_t src_len,
    uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    return base85_decode(src, src_len, dst, dst_cap, out_len);
}

/* =========================================================================
 * Encoding — Bech32
 * =========================================================================*/
#include "../../modern/encoding/bech32.h"

int nextssl_enc_bech32_encode(
    const char *hrp, const uint8_t *data5, size_t data5_len,
    int use_m, char *dst, size_t dst_cap)
{
    return bech32_encode(hrp, data5, data5_len, use_m, dst, dst_cap);
}

int nextssl_enc_bech32_decode(
    const char *src, size_t src_len,
    char *hrp_out, size_t hrp_cap,
    uint8_t *data5, size_t data5_cap, size_t *data5_len,
    int *use_m_out)
{
    return bech32_decode(src, src_len, hrp_out, hrp_cap, data5, data5_cap, data5_len, use_m_out);
}

int nextssl_enc_bech32_convert_bits(
    uint8_t *out, size_t *out_len, int out_bits,
    const uint8_t *in, size_t in_len, int in_bits, int pad)
{
    return bech32_convert_bits(out, out_len, out_bits, in, in_len, in_bits, pad);
}

/* =========================================================================
 * Encoding — CRC32 / CRC64
 * =========================================================================*/
#include "../../modern/encoding/crc32.h"
#include "../../modern/encoding/crc64.h"

uint32_t nextssl_enc_crc32(const uint8_t *data, size_t len)                     { return crc32_compute(data, len); }
uint32_t nextssl_enc_crc32_update(uint32_t crc, const uint8_t *data, size_t len) { return crc32_update(crc, data, len); }
uint64_t nextssl_enc_crc64(const uint8_t *data, size_t len)                     { return crc64_compute(data, len); }
uint64_t nextssl_enc_crc64_update(uint64_t crc, const uint8_t *data, size_t len) { return crc64_update(crc, data, len); }

/* =========================================================================
 * Encoding — PEM
 * =========================================================================*/
#include "../../modern/encoding/pem.h"

int nextssl_enc_pem_encode(
    const char *type, const uint8_t *der, size_t der_len,
    char *dst, size_t dst_cap, size_t *out_len)
{
    return pem_encode(type, der, der_len, dst, dst_cap, out_len);
}

int nextssl_enc_pem_decode(
    const char *pem, size_t pem_len,
    char *type_out, size_t type_cap,
    uint8_t *der_out, size_t der_cap, size_t *der_len)
{
    return pem_decode(pem, pem_len, type_out, type_cap, der_out, der_cap, der_len);
}
