/* sm2.h — SM2 ECC (GB/T 32918)
 *
 * SM2 is the Chinese national ECC standard (prime-256 curve defined in GB/T 32918).
 * It covers:
 *   - Key generation
 *   - Signature scheme (analogous to ECDSA, using SM3 hash internally)
 *   - Key exchange (ECDH variant)
 *   - Asymmetric encryption (ECIES variant)
 *
 * Backend: GmSSL (libgmssl; Apache-2.0 licence).
 * Requires: -DNEXTSSL_HAS_GMSSL and -I<gmssl-install>/include at compile time,
 *           and linking against -lgmssl.
 */
#ifndef SM2_H
#define SM2_H

#ifdef NEXTSSL_HAS_GMSSL

#include <stddef.h>
#include <stdint.h>
#include <gmssl/sm2.h>   /* SM2_KEY, sm2_key_generate, sm2_do_sign, etc. */
#include <gmssl/sm3.h>   /* used internally for signing */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Signature size constants
 * The DER-encoded SM2 signature is variable-length (typically 70-72 bytes).
 * SM2_SIGNATURE_MAX_SIZE is a conservative upper bound.
 * ------------------------------------------------------------------------- */
#define SM2_SIGNATURE_MAX_SIZE  80u
#define SM2_DIGEST_SIZE         32u    /* SM3 output, used as message digest */

/* -------------------------------------------------------------------------
 * Key lifecycle
 * The SM2_KEY struct (defined in <gmssl/sm2.h>) contains both the private
 * scalar and the public point.  It is safe to copy by value.
 * ------------------------------------------------------------------------- */

/**
 * Generate a random SM2 key pair.
 * @param key  Output key struct.
 * @return 1 on success, 0 on error.
 */
static inline int sm2_keygen(SM2_KEY *key)
{
    return sm2_key_generate(key) == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Sign / Verify
 *
 * SM2 signing operates on a 32-byte digest, NOT the raw message.
 * The caller is responsible for computing SM3(ZA || message) where ZA
 * is the signer-specific hash from sm2_public_key_digest(), per GM/T 0009-2012.
 * For simple use, pass SM3(message) directly (skipping ZA for non-standard use).
 * ------------------------------------------------------------------------- */

/**
 * Sign a 32-byte digest.
 *
 * @param key  Signing key (private key must be set).
 * @param dgst 32-byte message digest.
 * @param sig  Output signature.
 * @return 1 on success, 0 on error.
 */
int sm2_sign(const SM2_KEY *key,
             const uint8_t dgst[SM2_DIGEST_SIZE],
             SM2_SIGNATURE *sig);

/**
 * Verify a signature against a 32-byte digest.
 *
 * @param key  Verification key (public key must be set).
 * @param dgst 32-byte digest.
 * @param sig  Signature to verify.
 * @return 1 if valid, 0 if invalid.
 */
int sm2_verify(const SM2_KEY *key,
               const uint8_t dgst[SM2_DIGEST_SIZE],
               const SM2_SIGNATURE *sig);

/**
 * Sign a 32-byte digest and DER-encode the signature into |out|.
 *
 * @param key     Signing key.
 * @param dgst    32-byte digest.
 * @param out     Output buffer for DER-encoded signature.
 * @param out_len In: capacity (>= SM2_SIGNATURE_MAX_SIZE).  Out: bytes written.
 * @return 1 on success, 0 on error.
 */
int sm2_sign_der(const SM2_KEY *key,
                 const uint8_t dgst[SM2_DIGEST_SIZE],
                 uint8_t *out, size_t *out_len);

/**
 * Verify a DER-encoded signature.
 *
 * @param key     Verification key.
 * @param dgst    32-byte digest.
 * @param sig     DER-encoded signature bytes.
 * @param sig_len Signature length.
 * @return 1 if valid, 0 if invalid.
 */
int sm2_verify_der(const SM2_KEY *key,
                   const uint8_t dgst[SM2_DIGEST_SIZE],
                   const uint8_t *sig, size_t sig_len);

/* -------------------------------------------------------------------------
 * Encrypt / Decrypt (SM2-ECIES, C1C3C2 DER format)
 * ------------------------------------------------------------------------- */

/**
 * Encrypt a message with the recipient's public key.
 *
 * @param key    Recipient's public key.
 * @param in     Plaintext.
 * @param inlen  Plaintext length.
 * @param out    Output buffer for DER-encoded ciphertext.
 * @param outlen In: capacity.  Out: bytes written.
 * @return 1 on success, 0 on error.
 */
int sm2_enc(const SM2_KEY *key,
            const uint8_t *in, size_t inlen,
            uint8_t *out, size_t *outlen);

/**
 * Decrypt a ciphertext with the recipient's private key.
 *
 * @param key    Recipient's keypair (private key must be set).
 * @param in     DER-encoded ciphertext.
 * @param inlen  Ciphertext length.
 * @param out    Output buffer for decrypted plaintext.
 * @param outlen In: capacity.  Out: bytes written.
 * @return 1 on success, 0 on error (decryption failure).
 */
int sm2_dec(const SM2_KEY *key,
            const uint8_t *in, size_t inlen,
            uint8_t *out, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_HAS_GMSSL */
#endif /* SM2_H */
