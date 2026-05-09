/* ed448.h — Ed448-Goldilocks EdDSA signature surface (RFC 8032 §5.2)
 *
 * Ed448 is the Edwards-curve Digital Signature Algorithm over Ed448-Goldilocks.
 * Keys are 57 bytes; signatures are 114 bytes.
 *
 * This is a clean public surface that delegates to _curve448_backend.
 * Keep distinct from x448 (key agreement) and curve448 (raw DH field).
 */
#ifndef NEXTSSL_ED448_H
#define NEXTSSL_ED448_H

#include <stdint.h>
#include <stddef.h>

#define ED448_PRIVATE_KEY_SIZE  57u   /* secret scalar */
#define ED448_PUBLIC_KEY_SIZE   57u   /* compressed point */
#define ED448_KEYPAIR_SIZE      114u  /* priv (57) || pub (57) — wolfSSL layout */
#define ED448_SIGNATURE_SIZE    114u  /* (R, S) */

/* Generate an Ed448 key pair from OS entropy.
 * private_key: ED448_PRIVATE_KEY_SIZE bytes output
 * public_key:  ED448_PUBLIC_KEY_SIZE  bytes output
 * Returns 0 on success, -1 on error. */
int ed448_keygen(uint8_t private_key[ED448_PRIVATE_KEY_SIZE],
                 uint8_t public_key[ED448_PUBLIC_KEY_SIZE]);

/* Sign a message using Ed448 (pure, no pre-hash).
 * context: optional context string (0–255 bytes); NULL means empty
 * sig:     ED448_SIGNATURE_SIZE bytes output
 * Returns 0 on success, -1 on error. */
int ed448_sign(const uint8_t *private_key, size_t priv_len,
               const uint8_t *public_key,  size_t pub_len,
               const uint8_t *msg,         size_t msg_len,
               const uint8_t *context,     uint8_t context_len,
               uint8_t        sig[ED448_SIGNATURE_SIZE]);

/* Verify an Ed448 signature.
 * Returns 0 if valid, -1 if invalid or error. */
int ed448_verify(const uint8_t *public_key,  size_t pub_len,
                 const uint8_t *msg,          size_t msg_len,
                 const uint8_t *sig,          size_t sig_len,
                 const uint8_t *context,      uint8_t context_len);

/* Ed448ph — pre-hash variant (hash the message with SHAKE256 before signing).
 * hash must be ED448_PREHASH_SIZE (64) bytes.
 * Returns 0 on success, -1 on error. */
int ed448ph_sign(const uint8_t *private_key, size_t priv_len,
                 const uint8_t *public_key,  size_t pub_len,
                 const uint8_t  hash[64],
                 const uint8_t *context,     uint8_t context_len,
                 uint8_t        sig[ED448_SIGNATURE_SIZE]);

int ed448ph_verify(const uint8_t *public_key,  size_t pub_len,
                   const uint8_t  hash[64],
                   const uint8_t *sig,          size_t sig_len,
                   const uint8_t *context,      uint8_t context_len);

#endif /* NEXTSSL_ED448_H */
