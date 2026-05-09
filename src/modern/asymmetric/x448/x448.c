/* x448.c — X448 Diffie-Hellman surface (RFC 7748 §5)
 *
 * Thin surface wrapper over _curve448_backend.
 * All scalar-field arithmetic is performed by wc_curve448_shared_secret_ex
 * and wc_curve448_make_key from the wolfSSL-derived backend.
 */
#include "x448.h"
#include "../_curve448_backend/curve448.h"
#include "../_curve448_backend/wolf_shim.h"
#include "../../common/secure_zero.h"
#include <string.h>

/* Entropy wiring -- reuse project DRBG */
extern int rng_fill(void *buf, size_t len);

void x448_clamp(uint8_t scalar[X448_KEY_SIZE])
{
    /* RFC 7748 §5: curve448 clamp — clear bits 0,1 of byte 0; set MSB of byte 55 */
    scalar[0]  &= 0xFC;
    scalar[55] |= 0x80;
}

int x448_scalarmult_base(uint8_t       public_key[X448_KEY_SIZE],
                         const uint8_t scalar[X448_KEY_SIZE])
{
    if (!public_key || !scalar) return -1;
    int ret = wc_curve448_make_pub(X448_KEY_SIZE, (byte *)public_key,
                                   X448_KEY_SIZE, (const byte *)scalar);
    return (ret == 0) ? 0 : -1;
}

int x448_scalarmult(uint8_t       out[X448_KEY_SIZE],
                    const uint8_t scalar[X448_KEY_SIZE],
                    const uint8_t public_key[X448_KEY_SIZE])
{
    if (!out || !scalar || !public_key) return -1;

    curve448_key priv, pub;
    wc_curve448_init(&priv);
    wc_curve448_init(&pub);

    int ret = -1;
    if (wc_curve448_import_private(scalar, X448_KEY_SIZE, &priv) != 0) goto done;
    if (wc_curve448_import_public(public_key, X448_KEY_SIZE, &pub) != 0) goto done;

    word32 outlen = X448_KEY_SIZE;
    if (wc_curve448_shared_secret_ex(&priv, &pub,
                                     (byte *)out, &outlen,
                                     EC448_LITTLE_ENDIAN) != 0) goto done;

    /* Reject the all-zero output (RFC 7748 §6.2) */
    uint8_t check = 0;
    for (size_t i = 0; i < X448_KEY_SIZE; i++) check |= out[i];
    ret = (check != 0) ? 0 : -1;

done:
    wc_curve448_free(&priv);
    wc_curve448_free(&pub);
    return ret;
}

int x448_keygen(uint8_t private_key[X448_KEY_SIZE],
                uint8_t public_key[X448_KEY_SIZE])
{
    if (!private_key || !public_key) return -1;

    /* Sample raw scalar from OS entropy, clamp, compute public key */
    if (rng_fill(private_key, X448_KEY_SIZE) != 0) return -1;
    x448_clamp(private_key);
    return x448_scalarmult_base(public_key, private_key);
}
