/* ecmqv.h — Elliptic-Curve MQV authenticated key agreement (SP 800-56A Rev 3)
 *
 * ECMQV is a two-party authenticated key agreement scheme that uses
 * two ephemeral + one static key per party, providing implicit authentication.
 *
 * Based on: NIST SP 800-56A Rev 3 §6.1.3
 * Reference: examples/c/ecmqv/
 *
 * Supports P-256 (most common; extend as needed).
 */
#ifndef NEXTSSL_ECMQV_H
#define NEXTSSL_ECMQV_H

#include <stdint.h>
#include <stddef.h>

#define ECMQV_P256_ORDER_BYTES  32u
#define ECMQV_P256_PUBKEY_BYTES 64u  /* x(32)||y(32) */
#define ECMQV_P256_SHARED_BYTES 32u

/* ecmqv_p256_shared_secret — compute MQV shared secret on P-256.
 *
 * Party A calls with:
 *   our_static_priv   : A's long-term private key (32 bytes)
 *   our_ephemeral_priv: A's ephemeral private key  (32 bytes)
 *   our_ephemeral_pub : A's ephemeral public key   (64 bytes)
 *   their_static_pub  : B's long-term public key   (64 bytes)
 *   their_ephemeral_pub: B's ephemeral public key  (64 bytes)
 *   shared            : 32-byte output shared secret
 *
 * Returns 0 on success, -1 on error.
 */
int ecmqv_p256_shared_secret(
        const uint8_t our_static_priv[ECMQV_P256_ORDER_BYTES],
        const uint8_t our_ephemeral_priv[ECMQV_P256_ORDER_BYTES],
        const uint8_t our_ephemeral_pub[ECMQV_P256_PUBKEY_BYTES],
        const uint8_t their_static_pub[ECMQV_P256_PUBKEY_BYTES],
        const uint8_t their_ephemeral_pub[ECMQV_P256_PUBKEY_BYTES],
        uint8_t       shared[ECMQV_P256_SHARED_BYTES]);

#endif /* NEXTSSL_ECMQV_H */
