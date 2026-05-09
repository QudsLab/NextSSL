/* rsa_pss.h — RSA-PSS signature surface (RFC 8017 §9.1 / FIPS 186-4)
 *
 * Thin surface over the existing asymmetric/rsa module.
 * Use this header when you need only the PSS scheme; rsa.h exposes both
 * PSS and PKCS#1 v1.5.
 */
#ifndef NEXTSSL_RSA_PSS_H
#define NEXTSSL_RSA_PSS_H

#include "../rsa/rsa.h"

/* RSA-PSS sign.
 * Delegates to rsa_pss_sign(); see rsa.h for full parameter documentation.
 * Returns 1 on success, 0 on failure (BearSSL convention). */
static inline int rsa_pss_sign_wrap(const rsa_keypair_t *kp,
                                     const br_hash_class * const *hf,
                                     const br_hash_class * const *mf,
                                     const uint8_t *hash,  size_t hash_len,
                                     size_t salt_len,
                                     uint8_t *sig, size_t *sig_len)
{
    return (int)rsa_pss_sign(kp, hf, mf, hash, hash_len, salt_len, sig, sig_len);
}

/* RSA-PSS verify.
 * Returns 1 if valid, 0 if invalid. */
static inline int rsa_pss_verify_wrap(const br_rsa_public_key *pk,
                                       const br_hash_class * const *hf,
                                       const br_hash_class * const *mf,
                                       const uint8_t *hash,  size_t hash_len,
                                       size_t salt_len,
                                       const uint8_t *sig, size_t sig_len)
{
    return (int)rsa_pss_verify(pk, hf, mf, hash, hash_len, salt_len, sig, sig_len);
}

#endif /* NEXTSSL_RSA_PSS_H */
