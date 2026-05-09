/* secp256k1.h — secp256k1 Koblitz curve surface (SEC2v2 §2.4.1)
 *
 * secp256k1 is the elliptic curve y² = x³ + 7 (mod p) where
 * p = 2^256 − 2^32 − 977.  Used by Bitcoin, Ethereum, and related systems.
 *
 * This is a thin surface over the _secp256k1 backend (to be wired to
 * bitcoin-core/secp256k1 or a compatible implementation).
 *
 * Key sizes: 32-byte private scalar, 33-byte compressed or 65-byte
 * uncompressed public point.
 */
#ifndef NEXTSSL_SECP256K1_H
#define NEXTSSL_SECP256K1_H

#include <stdint.h>
#include <stddef.h>

#define SECP256K1_PRIVKEY_SIZE    32u
#define SECP256K1_PUBKEY_UNCOMPRESSED_SIZE  65u  /* 0x04 || x(32) || y(32) */
#define SECP256K1_PUBKEY_COMPRESSED_SIZE    33u  /* 0x02/03 || x(32) */
#define SECP256K1_SIG_SIZE        64u  /* r(32) || s(32) */

/* secp256k1_keygen — generate a random key pair.
 * private_key: 32-byte output scalar
 * public_key : 65-byte uncompressed point output
 * Returns 0 on success, -1 on error. */
int secp256k1_keygen(uint8_t private_key[SECP256K1_PRIVKEY_SIZE],
                     uint8_t public_key[SECP256K1_PUBKEY_UNCOMPRESSED_SIZE]);

/* secp256k1_pubkey_from_privkey — derive public key from private key.
 * compressed: if non-zero, output a 33-byte compressed key; else 65-byte.
 * Returns 0 on success, -1 on error. */
int secp256k1_pubkey_from_privkey(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                   int compressed,
                                   uint8_t *pubkey, size_t *pubkey_len);

/* secp256k1_ecdh — Diffie-Hellman on secp256k1.
 * their_pubkey: 65-byte uncompressed or 33-byte compressed public key
 * our_privkey : 32-byte private scalar
 * shared      : 32-byte x-coordinate of the shared point (hash before use)
 * Returns 0 on success, -1 on error. */
int secp256k1_ecdh(const uint8_t *their_pubkey, size_t pub_len,
                   const uint8_t  our_privkey[SECP256K1_PRIVKEY_SIZE],
                   uint8_t        shared[32]);

/* secp256k1_sign — ECDSA sign (non-deterministic).
 * msg_hash: 32-byte pre-computed message hash
 * sig_r, sig_s: 32-byte output signature components
 * Returns 0 on success, -1 on error. */
int secp256k1_sign(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                   const uint8_t msg_hash[32],
                   uint8_t       sig_r[32],
                   uint8_t       sig_s[32]);

/* secp256k1_verify — ECDSA verify.
 * pubkey: 65-byte uncompressed or 33-byte compressed
 * Returns 0 if valid, -1 if invalid. */
int secp256k1_verify(const uint8_t *pubkey, size_t pub_len,
                     const uint8_t  msg_hash[32],
                     const uint8_t  sig_r[32],
                     const uint8_t  sig_s[32]);

#endif /* NEXTSSL_SECP256K1_H */
