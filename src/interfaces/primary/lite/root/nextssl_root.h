/**
 * @file root/nextssl_root.h (Lite)
 * @brief NextSSL Lite — Explicit-Algorithm (Root) Umbrella Header
 *
 * Including this header signals that you are operating OUTSIDE the safe
 * default path.  Every function here bypasses the active profile entirely —
 * the algorithm is hardcoded in the function name.
 *
 * Who should use this:
 *   - Protocol implementors that must match an external algorithm requirement
 *   - Test harnesses verifying known-answer vectors for specific algorithms
 *   - Any code that cannot accept the profile-selected default
 *
 * Who should NOT use this for normal application code:
 *   - Use nextssl_hash(), nextssl_encrypt(), etc. (the profile-driven defaults)
 *
 * Lite variant limits: MD5, SHA-1, legacy AEAD, extended ECC, and extended
 * PoW algorithms are NOT available here. Use the full variant's root/ for those.
 *
 * Algorithms available in lite root:
 *   Hash:  SHA-256, SHA-512, BLAKE3, Argon2id
 *   AEAD:  AES-256-GCM, ChaCha20-Poly1305
 *   ECC:   Ed25519 (sign/verify), X25519 (ECDH)
 *   PQC:   ML-KEM-1024, ML-DSA-87
 *   PoW:   SHA-256, SHA-512, BLAKE3, Argon2id
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_H
#define NEXTSSL_LITE_ROOT_H

#include <stddef.h>
#include <stdint.h>

/* -- Sub-group headers -- */
#include "hash/root_hash.h"
#include "core/root_aead.h"
#include "core/root_ecc.h"
#include "pqc/root_pqc_kem.h"
#include "pqc/root_pqc_sign.h"
#include "pow/root_pow.h"

/* ==========================================================================
 * Backwards-compatibility aliases (v0.0.1-alpha flat names → tree names)
 *
 * These inline wrappers let existing code continue to compile unmodified.
 * New code should call the nextssl_root_<group>_<algo>_<op>() names directly.
 *
 * BREAKING CHANGE NOTES:
 *   - nextssl_root_argon2id: now requires explicit t/m/p params.
 *     Compat macro uses hardcoded defaults (t=3, m=65536, p=4).
 *   - nextssl_root_x25519_keygen: old order was (pk, sk), new is (sk, pk).
 *     Compat wrapper swaps the args.
 *   - nextssl_root_mldsa87_verify: old returned 0=valid. New returns 1=valid.
 *     Compat wrapper re-normalises to old 0=valid convention.
 * ========================================================================== */

#ifdef __cplusplus
extern "C" {
#endif

/* Hash compat */
static inline int nextssl_root_sha256(const uint8_t *d, size_t l, uint8_t o[32])
    { return nextssl_root_hash_sha256(d, l, o); }
static inline int nextssl_root_sha512(const uint8_t *d, size_t l, uint8_t o[64])
    { return nextssl_root_hash_sha512(d, l, o); }
static inline int nextssl_root_blake3(const uint8_t *d, size_t l,
                                       uint8_t *o, size_t ol)
    { return nextssl_root_hash_blake3(d, l, o, ol); }
/* Argon2id compat — uses original hardcoded defaults */
static inline int nextssl_root_argon2id(const uint8_t *pw, size_t pwl,
                                         const uint8_t *salt, size_t saltl,
                                         uint8_t *out, size_t outl)
    { return nextssl_root_hash_argon2id(pw, pwl, salt, saltl, 3, 65536, 4, out, outl); }

/* AEAD compat — old sigs had no aad params (NULL, 0 filled in) */
static inline int nextssl_root_aes256gcm_encrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *pt, size_t pl, uint8_t *ct)
    { return nextssl_root_aead_aesgcm_encrypt(k, n, NULL, 0, pt, pl, ct); }
static inline int nextssl_root_aes256gcm_decrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *ct, size_t cl, uint8_t *pt)
    { return nextssl_root_aead_aesgcm_decrypt(k, n, NULL, 0, ct, cl, pt); }
static inline int nextssl_root_chacha20_encrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *pt, size_t pl, uint8_t *ct)
    { return nextssl_root_aead_chacha20_encrypt(k, n, NULL, 0, pt, pl, ct); }
static inline int nextssl_root_chacha20_decrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *ct, size_t cl, uint8_t *pt)
    { return nextssl_root_aead_chacha20_decrypt(k, n, NULL, 0, ct, cl, pt); }

/* ECC compat — old x25519_keygen was (pk, sk); new is (sk, pk) */
static inline int nextssl_root_x25519_keygen(uint8_t pk[32], uint8_t sk[32])
    { return nextssl_root_ecc_x25519_keygen(sk, pk); }
static inline int nextssl_root_x25519_exchange(const uint8_t my_sk[32],
    const uint8_t their_pk[32], uint8_t ss[32])
    { return nextssl_root_ecc_x25519_exchange(my_sk, their_pk, ss); }
static inline int nextssl_root_ed25519_keygen(uint8_t pk[32], uint8_t sk[64])
    { return nextssl_root_ecc_ed25519_keygen(pk, sk); }
/* old sig: (sig, msg, mlen, sk) */
static inline int nextssl_root_ed25519_sign(uint8_t sig[64],
    const uint8_t *msg, size_t mlen, const uint8_t sk[64])
    { return nextssl_root_ecc_ed25519_sign(sk, msg, mlen, sig); }
/* old sig: (sig, msg, mlen, pk) */
static inline int nextssl_root_ed25519_verify(const uint8_t sig[64],
    const uint8_t *msg, size_t mlen, const uint8_t pk[32])
    { return nextssl_root_ecc_ed25519_verify(pk, msg, mlen, sig); }

/* PQC KEM compat */
static inline int nextssl_root_mlkem1024_keygen(uint8_t *pk, uint8_t *sk)
    { return nextssl_root_pqc_kem_mlkem1024_keygen(pk, sk); }
static inline int nextssl_root_mlkem1024_encaps(const uint8_t *pk,
    uint8_t *ct, uint8_t ss[32])
    { return nextssl_root_pqc_kem_mlkem1024_encaps(pk, ct, ss); }
/* old decaps: (ct, sk, ss) → new: (sk, ct, ss) */
static inline int nextssl_root_mlkem1024_decaps(const uint8_t *ct,
    const uint8_t *sk, uint8_t ss[32])
    { return nextssl_root_pqc_kem_mlkem1024_decaps(sk, ct, ss); }

/* PQC Sign compat */
static inline int nextssl_root_mldsa87_keygen(uint8_t *pk, uint8_t *sk)
    { return nextssl_root_pqc_sign_mldsa87_keygen(pk, sk); }
/* old sign: (sig, sig_len, msg, mlen, sk) → new: (sk, msg, mlen, sig, sig_len) */
static inline int nextssl_root_mldsa87_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t mlen, const uint8_t *sk)
    { return nextssl_root_pqc_sign_mldsa87_sign(sk, msg, mlen, sig, sig_len); }
/* old verify returned 0=valid; new returns 1=valid — re-normalise */
static inline int nextssl_root_mldsa87_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t mlen, const uint8_t *pk)
    { return nextssl_root_pqc_sign_mldsa87_verify(pk, msg, mlen, sig, sig_len) == 1 ? 0 : -1; }

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_H */
