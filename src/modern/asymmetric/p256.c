/* p256.c — P-256 (NIST secp256r1) implementation via micro-ecc (Plan 205)
 *
 * Source: https://github.com/kmackay/micro-ecc  (BSD 2-clause)
 * Author: Ken MacKay
 *
 * micro-ecc provides only P-256 (secp256r1) of the NIST prime curves.
 * P-384 and P-521 require a different library (see p384.c / p521.c).
 *
 * RNG wiring: micro-ecc needs a callback for key generation entropy.
 * We wire it to rng_fill() from src/seed/rng/rng.h on first call.
 */
#include "p256.h"
#include "micro_ecc/uECC.h"
#include "../../seed/rng/rng.h"
#include <string.h>

/* ---- RNG callback wired to OS entropy ----------------------------------- */
static int p256_rng_cb(uint8_t *dest, unsigned size) {
    return (rng_fill(dest, (size_t)size) == 0) ? 1 : 0;
}

static void p256_ensure_rng(void) {
    if (uECC_get_rng() == NULL) {
        uECC_set_rng(p256_rng_cb);
    }
}

/* ---- Public API --------------------------------------------------------- */

int p256_keygen(uint8_t private_key[P256_PRIVATE_KEY_SIZE],
                uint8_t public_key[P256_PUBLIC_KEY_SIZE])
{
    p256_ensure_rng();
    /* micro-ecc: make_key(public_key, private_key, curve) — note arg order */
    return uECC_make_key(public_key, private_key, uECC_secp256r1()) ? 0 : -1;
}

int p256_ecdh(const uint8_t their_public[P256_PUBLIC_KEY_SIZE],
              const uint8_t our_private[P256_PRIVATE_KEY_SIZE],
              uint8_t       shared_secret[P256_SHARED_SECRET_SIZE])
{
    p256_ensure_rng();
    return uECC_shared_secret(their_public, our_private,
                              shared_secret, uECC_secp256r1()) ? 0 : -1;
}

int p256_ecdsa_sign(const uint8_t private_key[P256_PRIVATE_KEY_SIZE],
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *sig_r, uint8_t *sig_s)
{
    /* micro-ecc packs (r ‖ s) into one 64-byte buffer */
    uint8_t sig[P256_PRIVATE_KEY_SIZE * 2];
    p256_ensure_rng();
    (void)hash_len;
    if (!uECC_sign(private_key, msg_hash, (unsigned)hash_len,
                   sig, uECC_secp256r1())) return -1;
    memcpy(sig_r, sig,                         P256_PRIVATE_KEY_SIZE);
    memcpy(sig_s, sig + P256_PRIVATE_KEY_SIZE, P256_PRIVATE_KEY_SIZE);
    return 0;
}

int p256_ecdsa_verify(const uint8_t public_key[P256_PUBLIC_KEY_SIZE],
                      const uint8_t *msg_hash, size_t hash_len,
                      const uint8_t *sig_r, const uint8_t *sig_s)
{
    uint8_t sig[P256_PRIVATE_KEY_SIZE * 2];
    (void)hash_len;
    memcpy(sig,                         sig_r, P256_PRIVATE_KEY_SIZE);
    memcpy(sig + P256_PRIVATE_KEY_SIZE, sig_s, P256_PRIVATE_KEY_SIZE);
    return uECC_verify(public_key, msg_hash, (unsigned)hash_len,
                       sig, uECC_secp256r1()) ? 0 : -1;
}
