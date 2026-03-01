/**
 * @file root/nextssl_root.c
 * @brief NextSSL Full — Explicit-Algorithm (Root) Implementation
 *
 * Every function here bypasses the active profile and calls the named
 * primitive directly.  No profile dispatch — the algorithm is the function.
 *
 * Full variant additions over lite:
 *   - SHA-1, MD5 (legacy/alive)
 *   - ML-KEM-768 (medium security tier)
 *   - ML-DSA-65 (Dilithium3, medium security tier)
 *   - ML-DSA-87 (Dilithium5, high security — same as lite default)
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "nextssl_root.h"

/* Hash */
#include "../../../../primitives/hash/fast/sha256/sha256.h"
#include "../../../../primitives/hash/fast/sha512/sha512.h"
#include "../../../../primitives/hash/fast/blake3/blake3.h"

/* Legacy hashes (alive: usable for non-security checksums / compat) */
#include "../../../../legacy/alive/md5/md5.h"
#include "../../../../legacy/alive/sha1/sha1.h"

/* AEAD */
#include "../../../../primitives/aead/aes_gcm/aes_gcm.h"
#include "../../../../primitives/aead/chacha20_poly1305/chacha20_poly1305.h"

/* Classical asymmetric */
#include "../../../../primitives/ecc/ed25519/ed25519.h"

/* KDF */
#include "../../../../primitives/hash/memory_hard/Argon2id/argon2id.h"

/* Post-Quantum KEM */
#include "../../../../PQCrypto/crypto_kem/ml-kem-768/clean/api.h"

/* Post-Quantum Signatures */
#include "../../../../PQCrypto/crypto_sign/ml-dsa-65/clean/api.h"
#include "../../../../PQCrypto/crypto_sign/ml-dsa-87/clean/api.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ==========================================================================
 * CSPRNG helper (same as full nextssl.c)
 * ========================================================================== */

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
static int _root_rand(uint8_t *buf, size_t len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
#elif defined(__APPLE__)
#  include <unistd.h>
static int _root_rand(uint8_t *buf, size_t len) {
    /* getentropy is limited to 256 bytes per call on macOS */
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy((char *)buf + off, chunk) != 0) return -1;
        off += chunk;
    }
    return 0;
}
#else
#  include <sys/random.h>
static int _root_rand(uint8_t *buf, size_t len) {
    return getrandom(buf, len, 0) == (ssize_t)len ? 0 : -1;
}
#endif

/* ==========================================================================
 * Hash
 * ========================================================================== */

NEXTSSL_API int nextssl_root_sha256(const uint8_t *data, size_t len,
                                    uint8_t out[32]) {
    if (!data || !out) return -1;
    sha256(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_sha512(const uint8_t *data, size_t len,
                                    uint8_t out[64]) {
    if (!data || !out) return -1;
    sha512_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_blake3(const uint8_t *data, size_t len,
                                    uint8_t *out, size_t out_len) {
    if (!data || !out || out_len == 0) return -1;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out, out_len);
    return 0;
}

NEXTSSL_API int nextssl_root_sha1(const uint8_t *data, size_t len,
                                  uint8_t out[20]) {
    if (!data || !out) return -1;
    sha1_hash(data, len, out);
    return 0;
}

NEXTSSL_API int nextssl_root_md5(const uint8_t *data, size_t len,
                                 uint8_t out[16]) {
    if (!data || !out) return -1;
    md5_hash(data, len, out);
    return 0;
}

/* ==========================================================================
 * AEAD — Caller Supplies Nonce
 * Output layout: [ciphertext][16-byte tag]
 * ========================================================================== */

NEXTSSL_API int nextssl_root_aes256gcm_encrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t *pt, size_t plen,
                                               uint8_t *ct) {
    if (!key || !nonce || !pt || !ct) return -1;
    /* AES-GCM: writes [ciphertext][16-byte tag] to ct (plen+16 bytes) */
    AES_GCM_encrypt((uint8_t *)key, (uint8_t *)nonce,
                    NULL, 0,
                    (uint8_t *)pt, (int)plen,
                    ct);
    return 0;
}

NEXTSSL_API int nextssl_root_aes256gcm_decrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t *ct, size_t clen,
                                               uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || clen < 16) return -1;
    /* AES_GCM_decrypt: crtxtLen = plaintext bytes; tag sits at ct[crtxtLen..crtxtLen+15] */
    return AES_GCM_decrypt((uint8_t *)key, (uint8_t *)nonce,
                           NULL, 0,
                           (uint8_t *)ct, clen - 16,
                           pt) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_chacha20_encrypt(const uint8_t key[32],
                                              const uint8_t nonce[12],
                                              const uint8_t *pt, size_t plen,
                                              uint8_t *ct) {
    if (!key || !nonce || !pt || !ct) return -1;
    /* ChaCha20-Poly1305: writes [ciphertext][16-byte tag] to ct */
    ChaCha20_Poly1305_encrypt((uint8_t *)key, (uint8_t *)nonce,
                              NULL, 0,
                              (uint8_t *)pt, (int)plen,
                              ct);
    return 0;
}

NEXTSSL_API int nextssl_root_chacha20_decrypt(const uint8_t key[32],
                                              const uint8_t nonce[12],
                                              const uint8_t *ct, size_t clen,
                                              uint8_t *pt) {
    if (!key || !nonce || !ct || !pt || clen < 16) return -1;
    return ChaCha20_Poly1305_decrypt((uint8_t *)key, (uint8_t *)nonce,
                                     NULL, 0,
                                     (uint8_t *)ct, clen,
                                     pt) == 0 ? 0 : -1;
}

/* ==========================================================================
 * Classical Asymmetric
 * ========================================================================== */

NEXTSSL_API int nextssl_root_x25519_keygen(uint8_t pk[32], uint8_t sk[32]) {
    if (!pk || !sk) return -1;
    uint8_t seed[32];
    uint8_t sk_full[64];
    if (_root_rand(seed, 32) != 0) return -1;
    ed25519_create_keypair(pk, sk_full, seed);
    memcpy(sk, sk_full, 32); /* lower 32 bytes = scalar */
    memset(sk_full, 0, sizeof(sk_full));
    return 0;
}

NEXTSSL_API int nextssl_root_x25519_exchange(const uint8_t my_sk[32],
                                             const uint8_t their_pk[32],
                                             uint8_t ss[32]) {
    if (!my_sk || !their_pk || !ss) return -1;
    ed25519_key_exchange(ss, (uint8_t *)their_pk, (uint8_t *)my_sk);
    return 0;
}

NEXTSSL_API int nextssl_root_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]) {
    if (!pk || !sk) return -1;
    uint8_t seed[32];
    if (_root_rand(seed, 32) != 0) return -1;
    ed25519_create_keypair(pk, sk, seed);
    /* ed25519_sign expects sk[32..63] == public_key, so embed it now */
    memcpy(sk + 32, pk, 32);
    return 0;
}

NEXTSSL_API int nextssl_root_ed25519_sign(uint8_t sig[64],
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t sk[64]) {
    if (!sig || !msg || !sk) return -1;
    /* ed25519_sign needs pk (first 32B of sk || pk layout) */
    ed25519_sign(sig, msg, mlen, sk + 32, sk);
    return 0;
}

NEXTSSL_API int nextssl_root_ed25519_verify(const uint8_t sig[64],
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t pk[32]) {
    if (!sig || !msg || !pk) return -1;
    return ed25519_verify(sig, msg, mlen, pk) == 1 ? 1 : 0;
}

/* ==========================================================================
 * Post-Quantum KEM — ML-KEM-768
 * pk=1184B  sk=2400B  ct=1088B  ss=32B
 * ========================================================================== */

NEXTSSL_API int nextssl_root_mlkem768_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mlkem768_encaps(const uint8_t *pk,
                                             uint8_t *ct, uint8_t ss[32]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mlkem768_decaps(const uint8_t *ct,
                                             const uint8_t *sk,
                                             uint8_t ss[32]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

/* ==========================================================================
 * Post-Quantum Signatures — ML-DSA-65 (Dilithium3)
 * pk=1952B  sk=4032B  sig_max=3309B
 * ========================================================================== */

NEXTSSL_API int nextssl_root_mldsa65_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
               sig, sig_len, msg, mlen, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
               sig, sig_len, msg, mlen, pk) == 0 ? 1 : 0;
}

/* ==========================================================================
 * Post-Quantum Signatures — ML-DSA-87 (Dilithium5)
 * pk=2592B  sk=4896B  sig_max=4627B
 * ========================================================================== */

NEXTSSL_API int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
                                          const uint8_t *msg, size_t mlen,
                                          const uint8_t *sk) {
    if (!sig || !sig_len || !msg || !sk) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(
               sig, sig_len, msg, mlen, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_mldsa87_verify(const uint8_t *sig, size_t sig_len,
                                            const uint8_t *msg, size_t mlen,
                                            const uint8_t *pk) {
    if (!sig || !msg || !pk) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(
               sig, sig_len, msg, mlen, pk) == 0 ? 1 : 0;
}

/* ==========================================================================
 * Password / KDF
 * ========================================================================== */

NEXTSSL_API int nextssl_root_argon2id(const uint8_t *pw, size_t pw_len,
                                      const uint8_t *salt, size_t salt_len,
                                      uint8_t *out, size_t out_len) {
    if (!pw || !salt || !out || out_len == 0) return -1;
    return argon2id_hash_raw(3, 65536, 4,
                             pw, pw_len,
                             salt, salt_len,
                             out, out_len) == 0 ? 0 : -1;
}
