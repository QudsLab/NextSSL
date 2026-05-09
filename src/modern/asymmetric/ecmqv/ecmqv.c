/* ecmqv.c — Elliptic-Curve MQV authenticated key agreement (SP 800-56A Rev 3)
 *
 * MQV implicit key authentication on P-256.
 *
 * SP 800-56A §6.1.3 Algorithm:
 *   Let Q_s = our_ephemeral_pub, Q_u = their_ephemeral_pub
 *   Let s = order bit-length = 256, bar = ceil(s/2) = 128 (2^128)
 *   x_s = x-coordinate of Q_s (low-order coordinate)
 *   x_u = x-coordinate of Q_u
 *   implicit_s = (our_ephemeral_priv + (x_s mod 2^bar) * our_static_priv) mod n
 *   Z = (2^bar + x_u mod 2^bar) * their_ephemeral_pub + their_static_pub
 *   shared_secret = x-coordinate of (implicit_s * Z)
 *
 * NOTE: Full MQV requires bignum mod-n arithmetic and full P-256 point mult.
 * Reference: examples/c/ecmqv/ (SP 800-56A §C.2 example code)
 */
#include "ecmqv.h"
#include "../p256/p256.h"
#include <string.h>

int ecmqv_p256_shared_secret(
        const uint8_t our_static_priv[ECMQV_P256_ORDER_BYTES],
        const uint8_t our_ephemeral_priv[ECMQV_P256_ORDER_BYTES],
        const uint8_t our_ephemeral_pub[ECMQV_P256_PUBKEY_BYTES],
        const uint8_t their_static_pub[ECMQV_P256_PUBKEY_BYTES],
        const uint8_t their_ephemeral_pub[ECMQV_P256_PUBKEY_BYTES],
        uint8_t       shared[ECMQV_P256_SHARED_BYTES])
{
    if (!our_static_priv || !our_ephemeral_priv || !our_ephemeral_pub ||
        !their_static_pub || !their_ephemeral_pub || !shared) return -1;

    /* NOTE: Full SP 800-56A MQV requires scalar combination and point addition
     * via the P-256 backend (bignum mod-n).  Currently using plain ECDH
     * (ephemeral-only) as a compile-safe placeholder.
     * Replace with correct MQV arithmetic before deployment. */
    (void)our_static_priv;
    (void)our_ephemeral_pub;
    (void)their_static_pub;
    return p256_ecdh(their_ephemeral_pub, our_ephemeral_priv, shared);
}
