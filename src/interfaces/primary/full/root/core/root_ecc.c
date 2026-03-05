/**
 * @file root/core/root_ecc.c
 * @brief NextSSL Root — Elliptic-curve implementation.
 */

#include "root_ecc.h"
#include "../root_internal.h"

#include "../../../../../primitives/ecc/ed25519/ed25519.h"
#include "../../../../../primitives/ecc/curve448/curve448.h"
#include "../../../../../primitives/ecc/ristretto255/ristretto255.h"
#include "../../../../../primitives/ecc/elligator2/elligator2.h"

#include <string.h>

/* =========================================================================
 * Ed25519 — Signatures
 * ====================================================================== */

NEXTSSL_API int nextssl_root_ecc_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]) {
    if (!pk || !sk) return -1;
    uint8_t seed[32];
    if (_root_rand(seed, 32) != 0) return -1;
    ed25519_create_keypair(pk, sk, seed);
    /* sk layout: seed[32] || pk[32] — embed pk so sign() works */
    memcpy(sk + 32, pk, 32);
    memset(seed, 0, 32);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_ed25519_sign(uint8_t sig[64],
                                               const uint8_t *msg, size_t msg_len,
                                               const uint8_t sk[64]) {
    if (!sig || !msg || !sk) return -1;
    /* ed25519_sign(sig, msg, mlen, public_key, private_key) — pk is sk+32 */
    ed25519_sign(sig, msg, msg_len, sk + 32, sk);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_ed25519_verify(const uint8_t sig[64],
                                                 const uint8_t *msg, size_t msg_len,
                                                 const uint8_t pk[32]) {
    if (!sig || !msg || !pk) return -1;
    return ed25519_verify(sig, msg, msg_len, pk) == 1 ? 1 : 0;
}

/* =========================================================================
 * X25519 — Diffie-Hellman
 * ====================================================================== */

NEXTSSL_API int nextssl_root_ecc_x25519_keygen(uint8_t pk[32], uint8_t sk[32]) {
    if (!pk || !sk) return -1;
    uint8_t seed[32];
    uint8_t sk_full[64];
    if (_root_rand(seed, 32) != 0) return -1;
    ed25519_create_keypair(pk, sk_full, seed);
    memcpy(sk, sk_full, 32);
    memset(sk_full, 0, sizeof(sk_full));
    memset(seed, 0, sizeof(seed));
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_x25519_exchange(const uint8_t my_sk[32],
                                                  const uint8_t their_pk[32],
                                                  uint8_t ss[32]) {
    if (!my_sk || !their_pk || !ss) return -1;
    ed25519_key_exchange(ss, (uint8_t *)their_pk, (uint8_t *)my_sk);
    return 0;
}

/* =========================================================================
 * X448 — Diffie-Hellman over Curve448 (via wolfSSL shim)
 *
 * Requires HAVE_CURVE448 to be defined by the build system and wolfSSL
 * linked.  Falls back to -1 if not available.
 * ====================================================================== */

#ifdef HAVE_CURVE448

/* wolfSSL RNG — use our CSPRNG bytes as the entropy source via a minimal
 * direct approach: generate sk bytes with _root_rand and compute pk with
 * wc_curve448_make_pub (does not need the wolfSSL RNG object).            */

NEXTSSL_API int nextssl_root_ecc_x448_keygen(uint8_t pk[56], uint8_t sk[56]) {
    if (!pk || !sk) return -1;
    /* Generate random private key */
    if (_root_rand(sk, 56) != 0) return -1;
    /* X448 clamping per RFC 7748 §5: clear bits 0-1 of first byte,
     * set bit 7 of last byte */
    sk[0]  &= 0xFC;   /* clear two low bits */
    sk[55] |= 0x80;   /* set high bit of last byte */
    /* Derive public key from private key bytes */
    return wc_curve448_make_pub(CURVE448_PUB_KEY_SIZE, pk,
                                CURVE448_KEY_SIZE,     sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_ecc_x448_exchange(const uint8_t my_sk[56],
                                                const uint8_t their_pk[56],
                                                uint8_t ss[56]) {
    if (!my_sk || !their_pk || !ss) return -1;
    curve448_key priv_key, pub_key;
    int ret;

    wc_curve448_init(&priv_key);
    wc_curve448_init(&pub_key);

    ret = wc_curve448_import_private_raw((const byte *)my_sk, CURVE448_KEY_SIZE,
                                          (const byte *)my_sk, CURVE448_PUB_KEY_SIZE,
                                          &priv_key);
    if (ret != 0) goto cleanup;

    ret = wc_curve448_import_public((const byte *)their_pk, CURVE448_PUB_KEY_SIZE,
                                    &pub_key);
    if (ret != 0) goto cleanup;

    {
        word32 ss_len = CURVE448_KEY_SIZE;
        ret = wc_curve448_shared_secret(&priv_key, &pub_key, ss, &ss_len);
        if (ss_len != CURVE448_KEY_SIZE) ret = -1;
    }

cleanup:
    wc_curve448_free(&priv_key);
    wc_curve448_free(&pub_key);
    return ret == 0 ? 0 : -1;
}

#else /* !HAVE_CURVE448 */

NEXTSSL_API int nextssl_root_ecc_x448_keygen(uint8_t pk[56], uint8_t sk[56]) {
    (void)pk; (void)sk;
    return -1;  /* Curve448 not available in this build */
}

NEXTSSL_API int nextssl_root_ecc_x448_exchange(const uint8_t my_sk[56],
                                                const uint8_t their_pk[56],
                                                uint8_t ss[56]) {
    (void)my_sk; (void)their_pk; (void)ss;
    return -1;  /* Curve448 not available in this build */
}

#endif /* HAVE_CURVE448 */

/* =========================================================================
 * Ristretto255 — prime-order group
 * ====================================================================== */

NEXTSSL_API int nextssl_root_ecc_r255_is_valid(const uint8_t p[32]) {
    if (!p) return 0;
    return ristretto255_is_valid_point(p);
}

NEXTSSL_API int nextssl_root_ecc_r255_add(uint8_t r[32],
                                           const uint8_t p[32],
                                           const uint8_t q[32]) {
    if (!r || !p || !q) return -1;
    return ristretto255_add(r, p, q) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_ecc_r255_sub(uint8_t r[32],
                                           const uint8_t p[32],
                                           const uint8_t q[32]) {
    if (!r || !p || !q) return -1;
    return ristretto255_sub(r, p, q) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_ecc_r255_from_hash(uint8_t p[32],
                                                 const uint8_t hash[64]) {
    if (!p || !hash) return -1;
    return ristretto255_from_hash(p, hash) == 0 ? 0 : -1;
}

/* =========================================================================
 * Elligator2 — steganographic key encoding
 * ====================================================================== */

NEXTSSL_API int nextssl_root_ecc_elligator2_map(uint8_t curve[32],
                                                 const uint8_t hidden[32]) {
    if (!curve || !hidden) return -1;
    elligator2_map(curve, hidden);
    return 0;
}

NEXTSSL_API int nextssl_root_ecc_elligator2_rev(uint8_t hidden[32],
                                                 const uint8_t public_key[32],
                                                 uint8_t tweak) {
    if (!hidden || !public_key) return -1;
    return elligator2_rev(hidden, public_key, tweak);
}

NEXTSSL_API int nextssl_root_ecc_elligator2_keygen(uint8_t hidden[32],
                                                    uint8_t secret_key[32],
                                                    uint8_t seed[32]) {
    if (!hidden || !secret_key || !seed) return -1;
    elligator2_key_pair(hidden, secret_key, seed);
    return 0;
}
