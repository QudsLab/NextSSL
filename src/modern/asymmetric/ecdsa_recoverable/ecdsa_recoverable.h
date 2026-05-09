/* ecdsa_recoverable.h — Recoverable ECDSA for secp256k1 (SEC1v2 §4.1.6)
 *
 * Recoverable ECDSA extends a standard secp256k1 signature with a 1-byte
 * recovery ID (v = 0 or 1, sometimes +27 for Ethereum legacy encoding).
 * The recovery ID allows verifiers to reconstruct the public key from the
 * signature and message hash alone (two possible keys; v selects the correct one).
 *
 * Used by: Ethereum transaction signing, Bitcoin compact signatures,
 *          libsecp256k1 ecdsa_sign_recoverable.
 *
 * Depends on the secp256k1 backend.
 */
#ifndef NEXTSSL_ECDSA_RECOVERABLE_H
#define NEXTSSL_ECDSA_RECOVERABLE_H

#include <stdint.h>
#include <stddef.h>

#define ECDSA_REC_SIG_SIZE  65u  /* r(32) || s(32) || v(1) */

/* ecdsa_recoverable_sign — sign and include recovery ID.
 * privkey  : 32-byte secp256k1 private key
 * msg_hash : 32-byte message hash (e.g. keccak256 for Ethereum)
 * sig      : 65-byte output: r(32) || s(32) || v(1)  where v ∈ {0, 1}
 * Returns 0 on success, -1 on error. */
int ecdsa_recoverable_sign(const uint8_t privkey[32],
                            const uint8_t msg_hash[32],
                            uint8_t       sig[ECDSA_REC_SIG_SIZE]);

/* ecdsa_recoverable_verify — verify signature and recover public key.
 * msg_hash : 32-byte message hash
 * sig      : 65-byte recoverable signature (r || s || v)
 * pubkey   : 65-byte output uncompressed public key
 * Returns 0 on success (key recovered), -1 on failure. */
int ecdsa_recoverable_verify(const uint8_t msg_hash[32],
                              const uint8_t sig[ECDSA_REC_SIG_SIZE],
                              uint8_t       pubkey[65]);

/* ecdsa_recoverable_verify_against_pubkey — verify with known public key.
 * Returns 0 if signature matches pubkey, -1 otherwise. */
int ecdsa_recoverable_verify_against_pubkey(
        const uint8_t *pubkey,   size_t pub_len,
        const uint8_t  msg_hash[32],
        const uint8_t  sig[ECDSA_REC_SIG_SIZE]);

#endif /* NEXTSSL_ECDSA_RECOVERABLE_H */
