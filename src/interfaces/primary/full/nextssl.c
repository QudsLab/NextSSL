/**
 * @file nextssl.c
 * @brief Full variant unified API implementation (Layer 4)
 *
 * Provides the NextSSL full-variant primary interface.
 * Profile-based immutable config — users pick an intent (MODERN / PQC / …),
 * not individual algorithm knobs.
 *
 * See GPT_CONV_012 design: "profiles over algorithm shopping, immutable after
 * init, defaults opinionated and hard, users think in use-cases not cipher
 * modes."
 */

/* Mark this translation unit as building the DLL so NEXTSSL_API = dllexport */
#define NEXTSSL_BUILDING_DLL

#include "nextssl.h"
/* Profile-based configuration system */
#include "../../../config/config.h"
/* Crypto primitives */
#include "../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../primitives/hash/fast/blake3/blake3.h"
#include "../../../primitives/aead/aes_gcm/aes_gcm.h"
#include "../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"
#include "../../../primitives/ecc/ed25519/ed25519.h"
#include "../../../PQCrypto/common/hkdf/hkdf.h"
#include "../../../primitives/hash/memory_hard/Argon2id/argon2id.h"
#include "../../../PQCrypto/crypto_kem/ml-kem-768/clean/api.h"
#include "../../../PQCrypto/crypto_sign/ml-dsa-65/clean/api.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ========================================================================== */
/*  CSPRNG                                                                     */
/* ========================================================================== */

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
static int os_random(uint8_t *buf, size_t len) {
    return SystemFunction036(buf, (ULONG)len) ? 0 : -1;
}
#else
#  include <stdio.h>
static int os_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}
#endif

/* ========================================================================== */
/*  Version / Variant                                                          */
/* ========================================================================== */

NEXTSSL_API const char* nextssl_version(void) {
    return "NextSSL v0.0.1-beta";
}

NEXTSSL_API const char* nextssl_variant(void) {
    return "full";
}

NEXTSSL_API const char* nextssl_security_level(void) {
    return nextssl_config_security_level();
}

/* ========================================================================== */
/*  Random                                                                     */
/* ========================================================================== */

NEXTSSL_API int nextssl_random(uint8_t *output, size_t length) {
    return os_random(output, length);
}

/* ========================================================================== */
/*  Hash  (SHA-256 default)                                                    */
/* ========================================================================== */

NEXTSSL_API int nextssl_hash(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32])
{
    if (!data || !hash) return -1;
    const nextssl_config_t *cfg = nextssl_config_get_or_default();
    switch (cfg->default_hash) {
        case NEXTSSL_HASH_SHA512: {
            uint8_t tmp[64];
            sha512_hash(data, data_len, tmp);
            memcpy(hash, tmp, 32);  /* first 32 bytes of SHA-512 */
            return 0;
        }
        case NEXTSSL_HASH_BLAKE3: {
            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, data, data_len);
            blake3_hasher_finalize(&h, hash, 32);
            return 0;
        }
        case NEXTSSL_HASH_SHA256:
        default:
            sha256(data, data_len, hash);
            return 0;
    }
}

/* ========================================================================== */
/*  Symmetric Encryption  (AES-256-GCM, auto nonce)                           */
/*                                                                             */
/*  Output layout: [12-byte nonce][ciphertext][16-byte GCM tag]               */
/*  Caller must allocate  plaintext_len + 28  bytes for ciphertext buffer.    */
/* ========================================================================== */

NEXTSSL_API int nextssl_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!key || !plaintext || !ciphertext || !ciphertext_len) return -1;

    uint8_t nonce[12];
    if (os_random(nonce, 12) != 0) return -2;

    /* Write nonce as first 12 bytes of output */
    memcpy(ciphertext, nonce, 12);

    const nextssl_config_t *cfg = nextssl_config_get_or_default();
    if (cfg->default_aead == NEXTSSL_AEAD_CHACHA20_POLY1305) {
        ChaCha20_Poly1305_encrypt(key, nonce, NULL, 0,
                                  plaintext, plaintext_len,
                                  ciphertext + 12);
    } else {
        /* AES-256-GCM (default) */
        AES_GCM_encrypt(key, nonce, NULL, 0, plaintext, plaintext_len,
                        ciphertext + 12);
    }

    *ciphertext_len = plaintext_len + 28;  /* 12 nonce + ct + 16 tag */
    return 0;
}

NEXTSSL_API int nextssl_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len)
{
    if (!key || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < 28) return -1;

    const uint8_t *nonce = ciphertext;           /* first 12 bytes */
    size_t pt_len = ciphertext_len - 28;

    const nextssl_config_t *cfg = nextssl_config_get_or_default();
    char ok;
    if (cfg->default_aead == NEXTSSL_AEAD_CHACHA20_POLY1305) {
        ok = ChaCha20_Poly1305_decrypt(key, nonce, NULL, 0,
                                       ciphertext + 12, pt_len + 16,
                                       plaintext);
    } else {
        /* AES-256-GCM (default) */
        ok = AES_GCM_decrypt(key, nonce, NULL, 0,
                             ciphertext + 12, pt_len,
                             plaintext);
    }
    if (ok != 0) return -3;

    *plaintext_len = pt_len;
    return 0;
}

/* ========================================================================== */
/*  Key Derivation  (HKDF-SHA256)                                              */
/* ========================================================================== */

NEXTSSL_API int nextssl_derive_key(
    const uint8_t *input, size_t input_len,
    const char *context,
    uint8_t *output, size_t output_len)
{
    if (!input || !output) return -1;

    size_t info_len = context ? strlen(context) : 0;
    return hkdf(NULL, 0,
                input, input_len,
                (const uint8_t *)context, info_len,
                output, output_len);
}

/* ========================================================================== */
/*  Password Hashing  (Argon2id — encoded string output)                      */
/* ========================================================================== */

#define ARGON2_T_COST      3
#define ARGON2_M_COST  65536   /* 64 MB */
#define ARGON2_PARALLEL    4
#define ARGON2_HASH_LEN   32
#define ARGON2_ENCODED_LEN 196  /* "$argon2id$v=19$..." fits in 196 bytes */

NEXTSSL_API int nextssl_password_hash(
    const char *password, size_t password_len,
    char *hash_output, size_t hash_output_len)
{
    if (!password || !hash_output || hash_output_len < ARGON2_ENCODED_LEN)
        return -1;

    /* Generate a random 16-byte salt internally */
    uint8_t salt[16];
    if (os_random(salt, 16) != 0) return -2;

    return argon2id_hash_encoded(
        ARGON2_T_COST, ARGON2_M_COST, ARGON2_PARALLEL,
        password, password_len,
        salt, 16,
        ARGON2_HASH_LEN,
        hash_output, hash_output_len);
}

NEXTSSL_API int nextssl_password_verify(
    const char *password, size_t password_len,
    const char *stored_hash)
{
    if (!password || !stored_hash) return -1;
    /* argon2id_verify returns 0 on success (ARGON2_OK = 0) */
    return argon2id_verify(stored_hash, password, password_len);
}

/* ========================================================================== */
/*  Key Exchange  (X25519)                                                     */
/* ========================================================================== */

NEXTSSL_API int nextssl_keyexchange_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32])
{
    if (!public_key || !secret_key) return -1;

    unsigned char seed[32];
    unsigned char sk_full[64];

    if (ed25519_create_seed(seed) != 0) return -2;
    ed25519_create_keypair(public_key, sk_full, seed);
    /* sk_full[0..31] is the clamped Curve25519 scalar */
    memcpy(secret_key, sk_full, 32);
    return 0;
}

NEXTSSL_API int nextssl_keyexchange_compute(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32])
{
    if (!shared_secret || !our_secret_key || !their_public_key) return -1;
    ed25519_key_exchange(shared_secret, their_public_key, our_secret_key);
    return 0;
}

/* ========================================================================== */
/*  Digital Signatures  (Ed25519)                                              */
/* ========================================================================== */

NEXTSSL_API int nextssl_sign_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[64])
{
    if (!public_key || !secret_key) return -1;

    unsigned char seed[32];
    if (ed25519_create_seed(seed) != 0) return -2;

    ed25519_create_keypair(public_key, secret_key, seed);
    /* Embed public key in secret_key[32..63] for use in ed25519_sign */
    memcpy(secret_key + 32, public_key, 32);
    return 0;
}

NEXTSSL_API int nextssl_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64])
{
    if (!signature || !message || !secret_key) return -1;
    /* secret_key[32..63] holds the public key */
    ed25519_sign(signature, message, message_len,
                 secret_key + 32, secret_key);
    return 0;
}

NEXTSSL_API int nextssl_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32])
{
    if (!signature || !message || !public_key) return -1;
    return ed25519_verify(signature, message, message_len, public_key) ? 1 : 0;
}

/* ========================================================================== */
/*  Post-Quantum KEM  (ML-KEM-768)                                             */
/*  pk=1184B  sk=2400B  ct=1088B  ss=32B                                       */
/* ========================================================================== */

NEXTSSL_API int nextssl_pq_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(public_key, secret_key);
}

NEXTSSL_API int nextssl_pq_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    if (!ciphertext || !shared_secret || !public_key) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext, shared_secret,
                                                  public_key);
}

NEXTSSL_API int nextssl_pq_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    if (!shared_secret || !ciphertext || !secret_key) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret, ciphertext,
                                                  secret_key);
}

/* ========================================================================== */
/*  Post-Quantum Signatures  (ML-DSA-65)                                       */
/*  pk=1952B  sk=4032B  sig up to 3309B                                        */
/* ========================================================================== */

NEXTSSL_API int nextssl_pq_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(public_key, secret_key);
}

NEXTSSL_API int nextssl_pq_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
        signature, signature_len,
        message, message_len,
        secret_key);
}

NEXTSSL_API int nextssl_pq_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key)
{
    if (!signature || !message || !public_key) return -1;
    /* 0 = valid, non-zero = invalid */
    return (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                signature, signature_len,
                message, message_len,
                public_key) == 0) ? 1 : 0;
}

/* ========================================================================== */
/*  Utility                                                                    */
/* ========================================================================== */

NEXTSSL_API void nextssl_secure_zero(void *data, size_t length) {
    if (!data || !length) return;
    volatile unsigned char *p = (volatile unsigned char *)data;
    while (length--) *p++ = 0;
}

NEXTSSL_API int nextssl_constant_compare(
    const void *a, const void *b, size_t length)
{
    if (!a || !b) return 0;
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < length; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff == 0 ? 1 : 0;
}

/* ========================================================================== */
/*  Initialization & Self-Test                                                 */
/* ========================================================================== */

/*
 * nextssl_init(profile)
 *
 * Profiles:
 *   0 = MODERN        (SHA-256 / AES-256-GCM / Ed25519 / X25519)
 *   1 = COMPLIANCE    (FIPS/NIST aligned)
 *   2 = PQC           (BLAKE3 / ML-DSA-87 / ML-KEM-1024, post-quantum only)
 *   3 = COMPATIBILITY (includes legacy algorithms)
 *   4 = EMBEDDED      (ChaCha20-Poly1305, small footprint)
 *   5 = RESEARCH      (all algorithms, experimental)
 *
 * Config is immutable after first successful call.
 * Calling again returns 0 (already initialized) without error.
 */
NEXTSSL_API int nextssl_init(int profile) {
    if ((unsigned)profile >= (unsigned)NEXTSSL_PROFILE_MAX) {
        profile = NEXTSSL_PROFILE_MODERN;
    }
    const nextssl_config_t *cfg =
        nextssl_config_init((nextssl_profile_t)profile);
    return (cfg != NULL || nextssl_config_get() != NULL) ? 0 : -1;
}

NEXTSSL_API int nextssl_init_custom(const nextssl_custom_profile_t *profile) {
    if (profile == NULL) return -1;
    nextssl_profile_custom_t internal;
    internal.hash  = (nextssl_hash_algo_t)profile->hash;
    internal.aead  = (nextssl_aead_algo_t)profile->aead;
    internal.kdf   = (nextssl_kdf_algo_t)profile->kdf;
    internal.sign  = (nextssl_sign_algo_t)profile->sign;
    internal.kem   = (nextssl_kem_algo_t)profile->kem;
    internal.name  = profile->name;
    const nextssl_config_t *cfg = nextssl_config_init_custom(&internal);
    if (cfg == NULL) {
        return (nextssl_config_get() != NULL) ? -2 : -3;
    }
    return 0;
}

NEXTSSL_API int nextssl_selftest(void) {
    /* Hash self-test */
    uint8_t hash[32];
    const uint8_t msg[] = "abc";
    const uint8_t expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    sha256(msg, 3, hash);
    if (!nextssl_constant_compare(hash, expected, 32)) return -1;

    /* Encrypt/decrypt round-trip */
    uint8_t key[32] = {0};
    uint8_t pt[16]  = "selftest payload";
    uint8_t ct[44], rt[16];
    size_t ct_len, rt_len;
    if (nextssl_encrypt(key, pt, 16, ct, &ct_len) != 0) return -2;
    if (nextssl_decrypt(key, ct, ct_len, rt, &rt_len) != 0) return -3;
    if (rt_len != 16 || memcmp(pt, rt, 16) != 0) return -3;

    /* X25519 key exchange round-trip */
    uint8_t pk_a[32], sk_a[32], pk_b[32], sk_b[32], ss_a[32], ss_b[32];
    if (nextssl_keyexchange_keypair(pk_a, sk_a) != 0) return -4;
    if (nextssl_keyexchange_keypair(pk_b, sk_b) != 0) return -4;
    if (nextssl_keyexchange_compute(ss_a, sk_a, pk_b) != 0) return -4;
    if (nextssl_keyexchange_compute(ss_b, sk_b, pk_a) != 0) return -4;
    if (!nextssl_constant_compare(ss_a, ss_b, 32)) return -4;

    /* Ed25519 sign/verify round-trip */
    uint8_t epk[32], esk[64], sig[64];
    if (nextssl_sign_keypair(epk, esk) != 0) return -5;
    if (nextssl_sign(sig, msg, 3, esk) != 0) return -5;
    if (nextssl_verify(sig, msg, 3, epk) != 1) return -5;

    return 0;
}

NEXTSSL_API void nextssl_cleanup(void) {
    /* Reset config so a subsequent nextssl_init() is accepted */
    nextssl_config_reset();
}
