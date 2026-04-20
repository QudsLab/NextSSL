/**
 * @file nss_shim.h
 * @brief NSS_Data shim layer — connects the sanitizer funnel to every
 *        algorithm entry point.
 *
 * DESIGN
 * ------
 * Every public algorithm function today takes raw (const uint8_t*, size_t).
 * The sanitizer produces NSS_Data{data, length, type}.
 *
 * This header provides two things:
 *
 *   1. NSS_CALL() macro — the one-liner that any *existing* algorithm entry
 *      can use to normalise its input at the very top of the function body
 *      without changing its public signature.
 *
 *   2. nss_<subsystem>_* inline wrappers — NSS_Data-accepting variants of
 *      every entry point that takes user-supplied message/key/password/IKM
 *      data.  These are thin: they call the macro then forward .data/.length
 *      to the underlying raw function.  No logic duplication.
 *
 * USAGE PATTERN A — keep raw public signature, sanitize internally
 * ----------------------------------------------------------------
 *   int nextssl_root_hash_sha256(const uint8_t *data, size_t len, uint8_t out[32])
 *   {
 *       NSS_CALL(data, len, NSS_TYPE_AUTO, _nss);   // _nss is the local NSS_Data
 *       return sha256_impl(_nss.data, _nss.length, out);
 *   }
 *
 * USAGE PATTERN B — accept NSS_Data directly (preferred for new internal code)
 * ----------------------------------------------------------------------------
 *   int result = nss_hash_sha256(&my_nss_data, out);
 *
 * VISIBILITY : internal — never exported
 * LAYER      : 0 / common
 * NAMESPACE  : nss_<subsystem>_*  (wrappers), NSS_CALL (macro)
 *
 * @version 1.0.0
 * @date 2026-03-13
 */

#ifndef NEXTSSL_COMMON_SANITIZER_SHIM_H
#define NEXTSSL_COMMON_SANITIZER_SHIM_H

#include "nextssl_sanitizer.h"

/* ---- Algorithm headers (interfaces/ not yet built — added when ready) ---- */

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * NSS_CALL — one-liner sanitizer gate for raw-signature functions.
 *
 * Declares a local NSS_Data variable named `_var`, calls nss_sanitize,
 * and returns the sanitizer error code immediately on failure.
 *
 * Parameters:
 *   _inp   — const void* input pointer (may be NULL for passthrough types)
 *   _len   — size_t length
 *   _type  — NSS_TYPE_* tag (use NSS_TYPE_AUTO for raw binary)
 *   _var   — name for the local NSS_Data variable
 *
 * After the macro, use _var.data and _var.length.
 *
 * For HEX/BASE64 types the decode buffer must be provided separately;
 * use nss_sanitize() directly in those cases.
 * =============================================================== */
#define NSS_CALL(_inp, _len, _type, _var)                           \
    NSS_Data _var;                                                  \
    do {                                                            \
        int _rc = nss_sanitize((_inp), (_len), (_type),             \
                                NULL, 0, &(_var));                  \
        if (_rc != 0) return _rc;                                   \
    } while (0)
/* ================================================================
 * HASH SHIMS
 * All hash functions accept any byte buffer.  NSS_TYPE_AUTO is the
 * correct tag — no conversion, zero copy.
 * ================================================================ */

static inline int nss_hash_sha256(const NSS_Data *d, uint8_t out[32])
{
    return nextssl_root_hash_sha256(d->data, d->length, out);
}

static inline int nss_hash_sha512(const NSS_Data *d, uint8_t out[64])
{
    return nextssl_root_hash_sha512(d->data, d->length, out);
}

static inline int nss_hash_blake3(const NSS_Data *d,
                                  uint8_t *out, size_t out_len)
{
    return nextssl_root_hash_blake3(d->data, d->length, out, out_len);
}

#ifndef NEXTSSL_BUILD_LITE
static inline int nss_hash_sha224(const NSS_Data *d, uint8_t out[28])
{
    return nextssl_root_hash_sha224(d->data, d->length, out);
}

static inline int nss_hash_sha3_256(const NSS_Data *d, uint8_t out[32])
{
    return nextssl_root_hash_sha3_256(d->data, d->length, out);
}

static inline int nss_hash_sha3_512(const NSS_Data *d, uint8_t out[64])
{
    return nextssl_root_hash_sha3_512(d->data, d->length, out);
}

static inline int nss_hash_sha3_224(const NSS_Data *d, uint8_t out[28])
{
    return nextssl_root_hash_sha3_224(d->data, d->length, out);
}

static inline int nss_hash_sha3_384(const NSS_Data *d, uint8_t out[48])
{
    return nextssl_root_hash_sha3_384(d->data, d->length, out);
}

static inline int nss_hash_keccak256(const NSS_Data *d, uint8_t out[32])
{
    return nextssl_root_hash_keccak256(d->data, d->length, out);
}

static inline int nss_hash_blake2b(const NSS_Data *d,
                                   uint8_t *out, size_t out_len)
{
    return nextssl_root_hash_blake2b(d->data, d->length, out, out_len);
}

static inline int nss_hash_blake2s(const NSS_Data *d,
                                   uint8_t *out, size_t out_len)
{
    return nextssl_root_hash_blake2s(d->data, d->length, out, out_len);
}
#endif /* NEXTSSL_BUILD_LITE */

/* ================================================================
 * SIGNATURE SHIMS (ECC — Ed25519)
 * message is user-supplied; key bytes are internal/fixed-size.
 * ================================================================ */

static inline int nss_sign_ed25519_sign(uint8_t sig[64],
                                        const NSS_Data *msg,
                                        const uint8_t sk[64])
{
    return nextssl_root_ecc_ed25519_sign(sig, msg->data, msg->length, sk);
}

static inline int nss_sign_ed25519_verify(const uint8_t sig[64],
                                          const NSS_Data *msg,
                                          const uint8_t pk[32])
{
    return nextssl_root_ecc_ed25519_verify(sig, msg->data, msg->length, pk);
}

/* ================================================================
 * PQC SIGNATURE SHIMS (ML-DSA, Falcon, SPHINCS+)
 * msg is user-supplied; keys are internal fixed-size buffers.
 * ================================================================ */

static inline int nss_pqc_sign_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                                             const NSS_Data *msg,
                                             const uint8_t *sk)
{
    return nextssl_root_pqc_sign_mldsa87_sign(sig, sig_len,
                                               msg->data, msg->length, sk);
}

static inline int nss_pqc_sign_mldsa87_verify(const uint8_t *sig, size_t sig_len,
                                               const NSS_Data *msg,
                                               const uint8_t *pk)
{
    return nextssl_root_pqc_sign_mldsa87_verify(sig, sig_len,
                                                 msg->data, msg->length, pk);
}

#ifndef NEXTSSL_BUILD_LITE
static inline int nss_pqc_sign_mldsa44_sign(uint8_t *sig, size_t *sig_len,
                                             const NSS_Data *msg,
                                             const uint8_t *sk)
{
    return nextssl_root_pqc_sign_mldsa44_sign(sig, sig_len,
                                               msg->data, msg->length, sk);
}

static inline int nss_pqc_sign_mldsa44_verify(const uint8_t *sig, size_t sig_len,
                                               const NSS_Data *msg,
                                               const uint8_t *pk)
{
    return nextssl_root_pqc_sign_mldsa44_verify(sig, sig_len,
                                                 msg->data, msg->length, pk);
}

static inline int nss_pqc_sign_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                                             const NSS_Data *msg,
                                             const uint8_t *sk)
{
    return nextssl_root_pqc_sign_mldsa65_sign(sig, sig_len,
                                               msg->data, msg->length, sk);
}

static inline int nss_pqc_sign_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                                               const NSS_Data *msg,
                                               const uint8_t *pk)
{
    return nextssl_root_pqc_sign_mldsa65_verify(sig, sig_len,
                                                 msg->data, msg->length, pk);
}
#endif /* NEXTSSL_BUILD_LITE */

/* ================================================================
 * AEAD SHIMS
 * plaintext and AAD are user-supplied (both go through NSS_Data).
 * key/nonce are fixed-size internal buffers — not sanitized here.
 *
 * Wraps the base-layer functions in core/aead (nextssl_base_aead_*).
 * ================================================================ */

/* Forward declarations for the base AEAD API (defined in core/aead/aead.h) */
NEXTSSL_BASE_API int nextssl_base_aead_encrypt_aes_gcm(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

NEXTSSL_BASE_API int nextssl_base_aead_decrypt_aes_gcm(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t *plaintext_len);

NEXTSSL_BASE_API int nextssl_base_aead_encrypt_chacha20_poly1305(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

NEXTSSL_BASE_API int nextssl_base_aead_decrypt_chacha20_poly1305(
    const uint8_t *key, size_t key_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t *plaintext_len);

static inline int nss_aead_encrypt_aes_gcm(const uint8_t *key, size_t key_len,
                                            const uint8_t *nonce, size_t nonce_len,
                                            const NSS_Data *plaintext,
                                            const NSS_Data *aad,
                                            uint8_t *ciphertext,
                                            size_t  *ciphertext_len)
{
    return nextssl_base_aead_encrypt_aes_gcm(
        key, key_len, nonce, nonce_len,
        plaintext->data, plaintext->length,
        aad ? aad->data : NULL, aad ? aad->length : 0,
        ciphertext, ciphertext_len);
}

static inline int nss_aead_decrypt_aes_gcm(const uint8_t *key, size_t key_len,
                                            const uint8_t *nonce, size_t nonce_len,
                                            const NSS_Data *ciphertext,
                                            const NSS_Data *aad,
                                            uint8_t *plaintext,
                                            size_t  *plaintext_len)
{
    return nextssl_base_aead_decrypt_aes_gcm(
        key, key_len, nonce, nonce_len,
        ciphertext->data, ciphertext->length,
        aad ? aad->data : NULL, aad ? aad->length : 0,
        plaintext, plaintext_len);
}

static inline int nss_aead_encrypt_chacha20(const uint8_t *key, size_t key_len,
                                             const uint8_t *nonce, size_t nonce_len,
                                             const NSS_Data *plaintext,
                                             const NSS_Data *aad,
                                             uint8_t *ciphertext,
                                             size_t  *ciphertext_len)
{
    return nextssl_base_aead_encrypt_chacha20_poly1305(
        key, key_len, nonce, nonce_len,
        plaintext->data, plaintext->length,
        aad ? aad->data : NULL, aad ? aad->length : 0,
        ciphertext, ciphertext_len);
}

static inline int nss_aead_decrypt_chacha20(const uint8_t *key, size_t key_len,
                                             const uint8_t *nonce, size_t nonce_len,
                                             const NSS_Data *ciphertext,
                                             const NSS_Data *aad,
                                             uint8_t *plaintext,
                                             size_t  *plaintext_len)
{
    return nextssl_base_aead_decrypt_chacha20_poly1305(
        key, key_len, nonce, nonce_len,
        ciphertext->data, ciphertext->length,
        aad ? aad->data : NULL, aad ? aad->length : 0,
        plaintext, plaintext_len);
}

/* ================================================================
 * MAC SHIMS (HMAC)
 * Both the message data AND the key are user-supplied → both
 * should come through NSS_Data at the public entry point.
 * The key is passed as a separate NSS_Data because it may arrive
 * in any format (hex, base64, raw bytes).
 * ================================================================ */

/* Forward declarations for the partial HMAC core API */
NEXTSSL_CORE_API int nextssl_partial_core_hmac_init(
    nextssl_partial_core_hmac_ctx_t *ctx,
    nextssl_hmac_algorithm_t algorithm,
    const uint8_t *key, size_t key_len);

NEXTSSL_CORE_API int nextssl_partial_core_hmac_update(
    nextssl_partial_core_hmac_ctx_t *ctx,
    const uint8_t *data, size_t data_len);

NEXTSSL_CORE_API int nextssl_partial_core_hmac_final(
    nextssl_partial_core_hmac_ctx_t *ctx,
    uint8_t *mac);

static inline int nss_mac_hmac_init(nextssl_partial_core_hmac_ctx_t *ctx,
                                    nextssl_hmac_algorithm_t algorithm,
                                    const NSS_Data *key)
{
    return nextssl_partial_core_hmac_init(ctx, algorithm,
                                          key->data, key->length);
}

static inline int nss_mac_hmac_update(nextssl_partial_core_hmac_ctx_t *ctx,
                                      const NSS_Data *data)
{
    return nextssl_partial_core_hmac_update(ctx, data->data, data->length);
}

/* final() writes output, no NSS_Data needed */
static inline int nss_mac_hmac_final(nextssl_partial_core_hmac_ctx_t *ctx,
                                     uint8_t *mac)
{
    return nextssl_partial_core_hmac_final(ctx, mac);
}

/* ================================================================
 * KDF SHIMS (HKDF)
 * IKM, salt, and info are all user-supplied.
 * ================================================================ */

/* Forward declaration (actual name from kdf.h) */
NEXTSSL_CORE_API int nextssl_partial_core_hkdf(
    nextssl_hkdf_algorithm_t algorithm,
    const uint8_t *salt,  size_t salt_len,
    const uint8_t *ikm,   size_t ikm_len,
    const uint8_t *info,  size_t info_len,
    uint8_t *okm,         size_t okm_len);

static inline int nss_kdf_hkdf(nextssl_hkdf_algorithm_t algorithm,
                                const NSS_Data *salt,
                                const NSS_Data *ikm,
                                const NSS_Data *info,
                                uint8_t *okm, size_t okm_len)
{
    return nextssl_partial_core_hkdf(
        algorithm,
        salt ? salt->data : NULL, salt ? salt->length : 0,
        ikm  ? ikm->data  : NULL, ikm  ? ikm->length  : 0,
        info ? info->data : NULL, info ? info->length  : 0,
        okm, okm_len);
}

/* ================================================================
 * PASSWORD HASH SHIMS (PoW layer: Argon2id, scrypt, bcrypt)
 * password is user-supplied and arrives via NSS_Data (may have been
 * a C string, a typed string, or raw bytes from the caller).
 * ================================================================ */

static inline int nss_pow_argon2id_hash(const NSS_Data *password,
                                        char *hash_out, size_t hash_out_len)
{
    return nextssl_base_pow_argon2id_hash(password->data, password->length,
                                          hash_out, hash_out_len);
}

static inline int nss_pow_argon2id_verify(const NSS_Data *password,
                                          const char *hash_encoded)
{
    return nextssl_base_pow_argon2id_verify(password->data, password->length,
                                            hash_encoded);
}

static inline int nss_pow_scrypt_hash(const NSS_Data *password,
                                      uint8_t hash_out[64],
                                      uint8_t salt_out[32])
{
    return nextssl_base_pow_scrypt_hash(password->data, password->length,
                                        hash_out, salt_out);
}

static inline int nss_pow_scrypt_verify(const NSS_Data *password,
                                        const uint8_t expected_hash[64],
                                        const uint8_t salt[32])
{
    return nextssl_base_pow_scrypt_verify(password->data, password->length,
                                          expected_hash, salt);
}

static inline int nss_pow_bcrypt_hash(const NSS_Data *password, uint8_t cost,
                                      char *hash_out, size_t hash_out_len)
{
    return nextssl_base_pow_bcrypt_hash(password->data, password->length,
                                        cost, hash_out, hash_out_len);
}

/* ================================================================
 * DHCM / KEY-EXCHANGE SHIMS
 * Public keys and shared secrets that originate from the caller
 * (e.g. received over the wire) go through NSS_Data.
 * Fixed-size key buffers generated internally do not need the shim.
 * ================================================================ */

/* X25519 exchange: both keys are caller-supplied (fixed 32-byte) */
static inline int nss_dhcm_x25519_exchange(uint8_t ss[32],
                                            const NSS_Data *our_sk,
                                            const NSS_Data *their_pk)
{
    if (our_sk->length != 32 || their_pk->length != 32)
        return -1; /* algorithm constraint: exact size required */
    return nextssl_root_ecc_x25519_exchange(our_sk->data, their_pk->data, ss);
}

static inline int nss_dhcm_x448_exchange(uint8_t ss[56],
                                          const NSS_Data *our_sk,
                                          const NSS_Data *their_pk)
{
    if (our_sk->length != 56 || their_pk->length != 56)
        return -1;
    return nextssl_root_ecc_x448_exchange(our_sk->data, their_pk->data, ss);
}

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_COMMON_SANITIZER_SHIM_H */
