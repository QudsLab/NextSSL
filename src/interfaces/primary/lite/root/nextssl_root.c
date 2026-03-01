/**
 * @file root/nextssl_root.c
 * @brief NextSSL Lite — Explicit-Algorithm Interface Implementation
 *
 * Each function here is a direct, profile-bypassing call to a specific
 * algorithm. No dispatch, no defaults, no fallbacks.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif
#include "nextssl_root.h"

/* Lite layer wrappers */
#include "../../../main/lite/hash.h"
#include "../../../main/lite/aead.h"
#include "../../../main/lite/keyexchange.h"
#include "../../../main/lite/signature.h"
#include "../../../main/lite/pqc.h"
#include "../../../main/lite/password.h"

/* Direct primitives for functions not covered by the lite wrappers */
#include "../../../../primitives/hash/fast/blake3/blake3.h"
#include "../../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"
#include "../../../../primitives/hash/memory_hard/Argon2id/argon2id.h"

#include <string.h>

/* ==========================================================================
 * Hash
 * ========================================================================== */

int nextssl_root_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (!data || !out) return -1;
    return nextssl_lite_hash("SHA-256", data, len, out);
}

int nextssl_root_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    if (!data || !out) return -1;
    return nextssl_lite_hash("SHA-512", data, len, out);
}

int nextssl_root_blake3(const uint8_t *data, size_t len,
                        uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, out_len);
    return 0;
}

/* ==========================================================================
 * AEAD — Caller supplies nonce, no nonce prepended in output
 * ========================================================================== */

int nextssl_root_aes256gcm_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t *pt, size_t plen,
                                   uint8_t *ct) {
    if (!key || !nonce || !pt || !ct) return -1;
    return nextssl_lite_aead_encrypt("AES-256-GCM", key, nonce,
                                     NULL, 0, pt, plen, ct);
}

int nextssl_root_aes256gcm_decrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t *ct, size_t clen,
                                   uint8_t *pt) {
    if (!key || !nonce || !ct || !pt) return -1;
    return nextssl_lite_aead_decrypt("AES-256-GCM", key, nonce,
                                     NULL, 0, ct, clen, pt);
}

int nextssl_root_chacha20_encrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t *pt, size_t plen,
                                  uint8_t *ct) {
    if (!key || !nonce || !pt || !ct) return -1;
    return nextssl_lite_aead_encrypt("ChaCha20-Poly1305", key, nonce,
                                     NULL, 0, pt, plen, ct);
}

int nextssl_root_chacha20_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t *ct, size_t clen,
                                  uint8_t *pt) {
    if (!key || !nonce || !ct || !pt) return -1;
    return nextssl_lite_aead_decrypt("ChaCha20-Poly1305", key, nonce,
                                     NULL, 0, ct, clen, pt);
}

/* ==========================================================================
 * Classical Key Operations
 * ========================================================================== */

int nextssl_root_x25519_keygen(uint8_t pk[32], uint8_t sk[32]) {
    if (!pk || !sk) return -1;
    return nextssl_lite_x25519_keygen(pk, sk);
}

int nextssl_root_x25519_exchange(const uint8_t my_sk[32],
                                 const uint8_t their_pk[32],
                                 uint8_t ss[32]) {
    if (!my_sk || !their_pk || !ss) return -1;
    return nextssl_lite_x25519_exchange(my_sk, their_pk, ss);
}

int nextssl_root_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]) {
    if (!pk || !sk) return -1;
    return nextssl_lite_ed25519_keygen(pk, sk);
}

int nextssl_root_ed25519_sign(uint8_t sig[64],
                              const uint8_t *msg, size_t mlen,
                              const uint8_t sk[64]) {
    if (!sig || !msg || !sk) return -1;
    return nextssl_lite_ed25519_sign(msg, mlen, sk, sig);
}

int nextssl_root_ed25519_verify(const uint8_t sig[64],
                                const uint8_t *msg, size_t mlen,
                                const uint8_t pk[32]) {
    if (!sig || !msg || !pk) return -1;
    /* lite wrapper returns 0=valid — normalise to 1=valid, 0=invalid */
    return nextssl_lite_ed25519_verify(msg, mlen, sig, pk) == 0 ? 1 : 0;
}

/* ==========================================================================
 * Post-Quantum
 * ========================================================================== */

int nextssl_root_mlkem1024_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return nextssl_lite_kyber1024_keygen(pk, sk);
}

int nextssl_root_mlkem1024_encaps(const uint8_t *pk,
                                  uint8_t *ct, uint8_t ss[32]) {
    if (!pk || !ct || !ss) return -1;
    return nextssl_lite_kyber1024_encaps(pk, ct, ss);
}

int nextssl_root_mlkem1024_decaps(const uint8_t *ct,
                                  const uint8_t *sk,
                                  uint8_t ss[32]) {
    if (!ct || !sk || !ss) return -1;
    return nextssl_lite_kyber1024_decaps(ct, sk, ss);
}

int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return nextssl_lite_dilithium5_keygen(pk, sk);
}

int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t mlen,
                               const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return nextssl_lite_dilithium5_sign(msg, mlen, sk, sig, sig_len);
}

int nextssl_root_mldsa87_verify(const uint8_t *sig, size_t sig_len,
                                const uint8_t *msg, size_t mlen,
                                const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    /* lite wrapper returns 0=valid — normalise to 1=valid, 0=invalid */
    return nextssl_lite_dilithium5_verify(msg, mlen, sig, sig_len, pk) == 0 ? 1 : 0;
}

/* ==========================================================================
 * Password / KDF
 * ========================================================================== */

int nextssl_root_argon2id(const uint8_t *pw, size_t pw_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t *out, size_t out_len) {
    if (!pw || !salt || !out) return -1;
    if (out_len == 0 || salt_len == 0) return -1;
    return argon2id_hash_raw(3, 65536, 4, pw, pw_len,
                              salt, salt_len, out, out_len);
}
