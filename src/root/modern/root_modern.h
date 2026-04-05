/* root_modern.h — Exported Modern Cryptography API (Plan 405)
 *
 * Covers: Symmetric (AES-CBC, AES-GCM, ChaCha20), MAC (HMAC, Poly1305),
 *         KDF (HKDF, PBKDF2), Asymmetric (Ed25519, X25519, P-256/384/521).
 */
#ifndef ROOT_MODERN_H
#define ROOT_MODERN_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Symmetric — AES-CBC
 * =========================================================================
 * key_len must be 16, 24, or 32 (AES-128/192/256).
 * iv must be exactly 16 bytes.
 * out buffer must be at least in_len bytes (CBC is length-preserving for
 * complete blocks; caller is responsible for padding).
 * Returns 0 on success, non-zero on error.
 */
NEXTSSL_API int nextssl_sym_aes_cbc_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_cbc_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-GCM
 * =========================================================================
 * key_len — 16, 24, or 32 bytes.
 * nonce   — 12 bytes (IETF / GCM standard nonce).
 * aad     — additional authenticated data (may be NULL if aad_len == 0).
 * tag_out — 16-byte authentication tag (encrypt only).
 * Returns 0 on success, -1 on authentication failure (decrypt) or bad args.
 */
NEXTSSL_API void nextssl_aead_aes_gcm_encrypt(
    const uint8_t *key,   size_t key_len,
    const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_gcm_decrypt(
    const uint8_t *key,   size_t key_len,
    const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — ChaCha20 (IETF: 12-byte nonce, 32-bit counter)
 * =========================================================================
 * key must be 32 bytes. nonce must be 12 bytes.
 * In-place (in == out) is supported.
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_sym_chacha20(
    const uint8_t *key,
    const uint8_t  nonce[12],
    uint32_t       counter,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * MAC — HMAC
 * =========================================================================
 * algo    — hash algorithm name: "sha256", "sha512", "blake3", etc.
 * key/key_len — HMAC key
 * msg/msg_len — message
 * out     — caller-allocated; must be >= digest_size of algo
 * out_len — IN: capacity; OUT: bytes written
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_mac_hmac(
    const char    *algo,
    const uint8_t *key,  size_t key_len,
    const uint8_t *msg,  size_t msg_len,
    uint8_t       *out,  size_t *out_len);

/* =========================================================================
 * MAC — Poly1305 (one-shot, RFC 8439)
 * =========================================================================
 * key must be 32 bytes. out receives 16-byte tag.
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_mac_poly1305(
    const uint8_t  key[32],
    const uint8_t *msg, size_t msg_len,
    uint8_t        out[16]);

/* =========================================================================
 * KDF — HKDF (RFC 5869)
 * =========================================================================
 * algo      — inner hash: "sha256", "sha512", etc. (NULL = "sha256")
 * salt/salt_len — salt (NULL = hash-length zero bytes)
 * ikm/ikm_len   — input key material
 * info/info_len — context info
 * out/out_len   — derived key output
 * Returns 0 on success, -1 on error or out_len ceiling exceeded.
 */
NEXTSSL_API int nextssl_kdf_hkdf(
    const char    *algo,
    const uint8_t *salt,  size_t salt_len,
    const uint8_t *ikm,   size_t ikm_len,
    const uint8_t *info,  size_t info_len,
    uint8_t       *out,   size_t out_len);

/* =========================================================================
 * KDF — PBKDF2 (RFC 2898)
 * =========================================================================
 * algo       — inner hash (NULL = "sha256")
 * pass/pass_len — password
 * salt/salt_len — salt (recommended >= 16 bytes)
 * iterations — iteration count (recommended >= 100,000 for SHA-256)
 * out/out_len   — derived key
 * Returns 0 on success, -1 on error.
 */
NEXTSSL_API int nextssl_kdf_pbkdf2(
    const char    *algo,
    const uint8_t *pass,  size_t pass_len,
    const uint8_t *salt,  size_t salt_len,
    uint32_t       iterations,
    uint8_t       *out,   size_t out_len);

/* =========================================================================
 * Asymmetric — Ed25519
 * =========================================================================
 * Keypair: pk = 32 bytes public, sk = 64 bytes private (seed ‖ public).
 * Sign: sig = 64 bytes. Verify: returns 1 valid / 0 invalid.
 */
NEXTSSL_API int nextssl_asym_ed25519_keypair(uint8_t *pk, uint8_t *sk);

NEXTSSL_API int nextssl_asym_ed25519_sign(
    uint8_t       *sig,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk,
    const uint8_t *sk);

NEXTSSL_API int nextssl_asym_ed25519_verify(
    const uint8_t *sig,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk);

/* =========================================================================
 * Asymmetric — X25519 (ECDH / key exchange)
 * =========================================================================
 * pk / sk — 32 bytes each.
 * shared  — 32-byte shared secret.
 */
NEXTSSL_API int nextssl_asym_x25519_keypair(uint8_t *pk, uint8_t *sk);

NEXTSSL_API int nextssl_asym_x25519_exchange(
    uint8_t       *shared,
    const uint8_t *sk,
    const uint8_t *their_pk);

/* =========================================================================
 * Asymmetric — P-256, P-384, P-521 (ECDH stubs)
 * =========================================================================
 * Returns -1 (stubs — replace with vetted implementation when needed).
 */
NEXTSSL_API int nextssl_asym_p256_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_asym_p256_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared);

NEXTSSL_API int nextssl_asym_p384_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_asym_p384_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared);

NEXTSSL_API int nextssl_asym_p521_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_asym_p521_ecdh(const uint8_t *their_pk,
    const uint8_t *our_sk, uint8_t *shared);

/* =========================================================================
 * Symmetric — AES-ECB
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_ecb_encrypt(
    const uint8_t *key,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_ecb_decrypt(
    const uint8_t *key,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES-CTR
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_ctr_encrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_ctr_decrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES-CFB
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_cfb_encrypt(
    const uint8_t *key,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_cfb_decrypt(
    const uint8_t *key,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES-OFB
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_ofb_encrypt(
    const uint8_t *key,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_ofb_decrypt(
    const uint8_t *key,
    const uint8_t  iv[16],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES-XTS
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_xts_encrypt(
    const uint8_t *keys,
    const uint8_t *tweak,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_xts_decrypt(
    const uint8_t *keys,
    const uint8_t *tweak,
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES-FPE (FF1)
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_fpe_encrypt(
    const uint8_t *key,
    uint8_t       *tweak, size_t tweak_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_aes_fpe_decrypt(
    const uint8_t *key,
    uint8_t       *tweak, size_t tweak_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * Symmetric — AES Key Wrap (RFC 3394)
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_aes_kw_wrap(
    const uint8_t *kek,
    const uint8_t *secret, size_t secret_len,
    uint8_t       *wrapped);

NEXTSSL_API int nextssl_sym_aes_kw_unwrap(
    const uint8_t *kek,
    const uint8_t *wrapped, size_t wrap_len,
    uint8_t       *secret);

/* =========================================================================
 * Symmetric — 3DES-CBC
 * =========================================================================*/
NEXTSSL_API int nextssl_sym_3des_cbc_encrypt(
    const uint8_t  key[24],
    const uint8_t  iv[8],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_sym_3des_cbc_decrypt(
    const uint8_t  key[24],
    const uint8_t  iv[8],
    const uint8_t *in, size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-CCM
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_aes_ccm_encrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_ccm_decrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-EAX
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_aes_eax_encrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_eax_decrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-GCM-SIV
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_aes_gcm_siv_encrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_gcm_siv_decrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-OCB
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_aes_ocb_encrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_ocb_decrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — AES-SIV
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_aes_siv_encrypt(
    const uint8_t *keys,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t        iv[16],
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_aes_siv_decrypt(
    const uint8_t *keys,
    const uint8_t  iv[16],
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * AEAD — ChaCha20-Poly1305
 * =========================================================================*/
NEXTSSL_API void nextssl_aead_chacha20_poly1305_encrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

NEXTSSL_API int nextssl_aead_chacha20_poly1305_decrypt(
    const uint8_t *key,   const uint8_t *nonce,
    const uint8_t *aad,   size_t aad_len,
    const uint8_t *in,    size_t in_len,
    uint8_t       *out);

/* =========================================================================
 * MAC — AES-CMAC
 * =========================================================================*/
NEXTSSL_API int nextssl_mac_aes_cmac(
    const uint8_t *key,
    const uint8_t *data, size_t data_len,
    uint8_t        mac[16]);

/* =========================================================================
 * MAC — SipHash
 * =========================================================================*/
NEXTSSL_API int nextssl_mac_siphash(
    const uint8_t  key[16],
    const uint8_t *in,  size_t in_len,
    uint8_t       *out, size_t out_len);

/* =========================================================================
 * Asymmetric — Ed448 (conditional)
 * =========================================================================*/
#ifdef HAVE_ED448
NEXTSSL_API int nextssl_asym_ed448_keypair(uint8_t pk[57], uint8_t sk[57]);

NEXTSSL_API int nextssl_asym_ed448_sign(
    uint8_t       *sig,   size_t *sig_len,
    const uint8_t *msg,   size_t  msg_len,
    const uint8_t  sk[57],
    const uint8_t *ctx,   size_t  ctx_len);

NEXTSSL_API int nextssl_asym_ed448_verify(
    const uint8_t *sig,   size_t  sig_len,
    const uint8_t *msg,   size_t  msg_len,
    const uint8_t  pk[57],
    const uint8_t *ctx,   size_t  ctx_len);
#endif

/* =========================================================================
 * Asymmetric — X448 / Curve448 (conditional)
 * =========================================================================*/
#ifdef HAVE_CURVE448
NEXTSSL_API int nextssl_asym_x448_keypair(uint8_t pk[56], uint8_t sk[56]);

NEXTSSL_API int nextssl_asym_x448_exchange(
    uint8_t       *shared,
    const uint8_t  sk[56],
    const uint8_t  their_pk[56]);
#endif

/* =========================================================================
 * Asymmetric — RSA
 * =========================================================================*/
NEXTSSL_API void *nextssl_asym_rsa_alloc(void);
NEXTSSL_API void  nextssl_asym_rsa_free(void *kp);
NEXTSSL_API int   nextssl_asym_rsa_keygen(void *kp, unsigned bits);

NEXTSSL_API int nextssl_asym_rsa_pkcs1_sign(
    const void    *kp,
    const uint8_t *hash, size_t hash_len,
    uint8_t       *sig,  size_t *sig_len);

NEXTSSL_API int nextssl_asym_rsa_pkcs1_verify(
    const void    *pk,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *sig,  size_t  sig_len);

NEXTSSL_API int nextssl_asym_rsa_oaep_encrypt(
    const void    *pk,
    const uint8_t *in,  size_t in_len,
    uint8_t       *out, size_t *out_len);

NEXTSSL_API int nextssl_asym_rsa_oaep_decrypt(
    const void    *kp,
    uint8_t       *data, size_t *data_len);

/* =========================================================================
 * Asymmetric — SM2 (conditional)
 * =========================================================================*/
#ifdef NEXTSSL_HAS_GMSSL
NEXTSSL_API int nextssl_asym_sm2_sign(
    const void    *key,
    const uint8_t  dgst[32],
    uint8_t       *sig, size_t *sig_len);

NEXTSSL_API int nextssl_asym_sm2_verify(
    const void    *key,
    const uint8_t  dgst[32],
    const uint8_t *sig, size_t sig_len);

NEXTSSL_API int nextssl_asym_sm2_encrypt(
    const void    *key,
    const uint8_t *in,  size_t  in_len,
    uint8_t       *out, size_t *out_len);

NEXTSSL_API int nextssl_asym_sm2_decrypt(
    const void    *key,
    const uint8_t *in,  size_t  in_len,
    uint8_t       *out, size_t *out_len);
#endif

/* =========================================================================
 * Encoding — Base58Check
 * =========================================================================*/
NEXTSSL_API int nextssl_enc_base58check_encode(
    uint8_t        version,
    const uint8_t *payload, size_t payload_len,
    char          *dst,     size_t dst_cap,
    size_t        *out_len);

NEXTSSL_API int nextssl_enc_base58check_decode(
    const char    *src,     size_t src_len,
    uint8_t       *version_out,
    uint8_t       *payload, size_t payload_cap,
    size_t        *payload_len);

/* =========================================================================
 * Encoding — Base62
 * =========================================================================*/
NEXTSSL_API int nextssl_enc_base62_encode(
    const uint8_t *src, size_t src_len,
    char          *dst, size_t dst_cap,
    size_t        *out_len);

NEXTSSL_API int nextssl_enc_base62_decode(
    const char    *src, size_t src_len,
    uint8_t       *dst, size_t dst_cap,
    size_t        *out_len);

/* =========================================================================
 * Encoding — Base85
 * =========================================================================*/
NEXTSSL_API int nextssl_enc_base85_encode(
    const uint8_t *src, size_t src_len,
    char          *dst, size_t dst_cap,
    size_t        *out_len);

NEXTSSL_API int nextssl_enc_base85_decode(
    const char    *src, size_t src_len,
    uint8_t       *dst, size_t dst_cap,
    size_t        *out_len);

/* =========================================================================
 * Encoding — Bech32
 * =========================================================================*/
NEXTSSL_API int nextssl_enc_bech32_encode(
    const char    *hrp,
    const uint8_t *data5, size_t data5_len,
    int            use_m,
    char          *dst,   size_t dst_cap);

NEXTSSL_API int nextssl_enc_bech32_decode(
    const char    *src,      size_t src_len,
    char          *hrp_out,  size_t hrp_cap,
    uint8_t       *data5,    size_t data5_cap,
    size_t        *data5_len,
    int           *use_m_out);

NEXTSSL_API int nextssl_enc_bech32_convert_bits(
    uint8_t       *out,     size_t *out_len, int out_bits,
    const uint8_t *in,      size_t  in_len,  int in_bits,
    int            pad);

/* =========================================================================
 * Encoding — CRC32 / CRC64
 * =========================================================================*/
NEXTSSL_API uint32_t nextssl_enc_crc32(const uint8_t *data, size_t len);
NEXTSSL_API uint32_t nextssl_enc_crc32_update(uint32_t crc, const uint8_t *data, size_t len);
NEXTSSL_API uint64_t nextssl_enc_crc64(const uint8_t *data, size_t len);
NEXTSSL_API uint64_t nextssl_enc_crc64_update(uint64_t crc, const uint8_t *data, size_t len);

/* =========================================================================
 * Encoding — PEM
 * =========================================================================*/
NEXTSSL_API int nextssl_enc_pem_encode(
    const char    *type,
    const uint8_t *der, size_t der_len,
    char          *dst, size_t dst_cap,
    size_t        *out_len);

NEXTSSL_API int nextssl_enc_pem_decode(
    const char    *pem,      size_t pem_len,
    char          *type_out, size_t type_cap,
    uint8_t       *der_out,  size_t der_cap,
    size_t        *der_len);

#ifdef __cplusplus
}
#endif

#endif /* ROOT_MODERN_H */
