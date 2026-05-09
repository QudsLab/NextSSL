/* rsa_pkcs1v15.h — RSA PKCS#1 v1.5 signature surface (RFC 8017 §9.2)
 *
 * Thin surface over the existing asymmetric/rsa module.
 * Use this header when you need only the PKCS#1 v1.5 scheme.
 */
#ifndef NEXTSSL_RSA_PKCS1V15_H
#define NEXTSSL_RSA_PKCS1V15_H

#include "../rsa/rsa.h"

/* RSA-PKCS1v15 sign.
 * Delegates to rsa_pkcs1_sign(); see rsa.h for full documentation.
 * Returns 1 on success, 0 on failure. */
static inline int rsa_pkcs1v15_sign(const rsa_keypair_t *kp,
                                     const unsigned char  *hash_oid,
                                     const uint8_t        *hash,
                                     size_t                hash_len,
                                     uint8_t              *sig,
                                     size_t               *sig_len)
{
    return (int)rsa_pkcs1_sign(kp, hash_oid, hash, hash_len, sig, sig_len);
}

/* RSA-PKCS1v15 verify.
 * Returns 1 if valid, 0 if invalid. */
static inline int rsa_pkcs1v15_verify(const br_rsa_public_key *pk,
                                       const unsigned char     *hash_oid,
                                       size_t                   hash_len,
                                       const uint8_t           *sig,
                                       size_t                   sig_len,
                                       uint8_t                 *hash_out)
{
    return (int)rsa_pkcs1_verify(pk, hash_oid, hash_len, sig, sig_len, hash_out);
}

#endif /* NEXTSSL_RSA_PKCS1V15_H */
