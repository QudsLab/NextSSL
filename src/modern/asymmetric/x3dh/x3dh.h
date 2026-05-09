/* x3dh.h — Extended Triple Diffie-Hellman (Signal X3DH protocol)
 *
 * X3DH is the key agreement protocol used by Signal for asynchronous
 * initial key exchange.  It uses four key pairs:
 *
 *   Sender side:
 *     IK_A: Alice's identity key pair (X25519 long-term)
 *     EK_A: Alice's ephemeral key pair (X25519, fresh per session)
 *
 *   Recipient side (pre-keys published to server):
 *     IK_B: Bob's identity key pair (X25519 long-term)
 *     SPK_B: Bob's signed pre-key (X25519, rotated periodically)
 *     OPK_B: Bob's one-time pre-key (X25519, consumed once)
 *
 * Shared key material:
 *   DH1 = DH(IK_A, SPK_B)
 *   DH2 = DH(EK_A, IK_B)
 *   DH3 = DH(EK_A, SPK_B)
 *   DH4 = DH(EK_A, OPK_B)  [omitted if OPK_B not available]
 *   SK   = KDF(DH1 || DH2 || DH3 [|| DH4])
 *
 * Reference: https://signal.org/docs/specifications/x3dh/
 *            examples/c/x3dh/
 */
#ifndef NEXTSSL_X3DH_H
#define NEXTSSL_X3DH_H

#include <stdint.h>
#include <stddef.h>

#define X3DH_KEY_SIZE     32u  /* X25519 key / shared secret size */
#define X3DH_SK_SIZE      32u  /* output shared key size */

/* x3dh_sender_shared_key — Alice computes the shared key.
 *
 * ik_a_priv : Alice's identity private key (32 bytes)
 * ek_a_priv : Alice's ephemeral private key (32 bytes)
 * ik_b_pub  : Bob's identity public key (32 bytes)
 * spk_b_pub : Bob's signed pre-key public key (32 bytes)
 * opk_b_pub : Bob's one-time pre-key public key (32 bytes, or NULL if unavailable)
 * sk        : 32-byte output shared key
 * Returns 0 on success, -1 on error. */
int x3dh_sender_shared_key(
        const uint8_t ik_a_priv[X3DH_KEY_SIZE],
        const uint8_t ek_a_priv[X3DH_KEY_SIZE],
        const uint8_t ik_b_pub[X3DH_KEY_SIZE],
        const uint8_t spk_b_pub[X3DH_KEY_SIZE],
        const uint8_t *opk_b_pub,             /* NULL if no OPK */
        uint8_t        sk[X3DH_SK_SIZE]);

/* x3dh_recipient_shared_key — Bob computes the shared key.
 *
 * ik_b_priv : Bob's identity private key (32 bytes)
 * spk_b_priv: Bob's signed pre-key private key (32 bytes)
 * opk_b_priv: Bob's one-time pre-key private key (32 bytes, or NULL)
 * ik_a_pub  : Alice's identity public key (32 bytes)
 * ek_a_pub  : Alice's ephemeral public key (32 bytes)
 * sk        : 32-byte output shared key
 * Returns 0 on success, -1 on error. */
int x3dh_recipient_shared_key(
        const uint8_t ik_b_priv[X3DH_KEY_SIZE],
        const uint8_t spk_b_priv[X3DH_KEY_SIZE],
        const uint8_t *opk_b_priv,            /* NULL if no OPK */
        const uint8_t ik_a_pub[X3DH_KEY_SIZE],
        const uint8_t ek_a_pub[X3DH_KEY_SIZE],
        uint8_t        sk[X3DH_SK_SIZE]);

#endif /* NEXTSSL_X3DH_H */
