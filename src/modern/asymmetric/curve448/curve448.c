/* curve448.c — Curve448 raw DH surface (RFC 7748 §5)
 *
 * Thin shim over _curve448_backend.  This surface exposes only the
 * canonical RFC 7748 scalar-multiply function with proper clamping.
 */
#include "curve448.h"
#include "../_curve448_backend/curve448.h"
#include "../_curve448_backend/wolf_shim.h"
#include <string.h>

void curve448_clamp(uint8_t scalar[CURVE448_SCALAR_SIZE])
{
    /* RFC 7748 §5: bits 0,1 of byte 0 cleared; MSB of byte 55 set */
    scalar[0]  &= 0xFC;
    scalar[55] |= 0x80;
}

int curve448(uint8_t       out[CURVE448_POINT_SIZE],
             const uint8_t scalar[CURVE448_SCALAR_SIZE],
             const uint8_t u[CURVE448_POINT_SIZE])
{
    if (!out || !scalar || !u) return -1;

    curve448_key priv, pub;
    wc_curve448_init(&priv);
    wc_curve448_init(&pub);

    /* Apply clamping on a copy — do not mutate caller's scalar */
    uint8_t sc[CURVE448_SCALAR_SIZE];
    memcpy(sc, scalar, CURVE448_SCALAR_SIZE);
    curve448_clamp(sc);

    int ret = -1;
    if (wc_curve448_import_private(sc, CURVE448_SCALAR_SIZE, &priv) != 0) goto done;
    if (wc_curve448_import_public(u, CURVE448_POINT_SIZE, &pub)      != 0) goto done;

    word32 out_len = CURVE448_POINT_SIZE;
    if (wc_curve448_shared_secret_ex(&priv, &pub,
                                     (byte *)out, &out_len,
                                     EC448_LITTLE_ENDIAN) != 0) goto done;

    /* Reject the all-zero output */
    uint8_t check = 0;
    for (size_t i = 0; i < CURVE448_POINT_SIZE; i++) check |= out[i];
    ret = (check != 0) ? 0 : -1;

done:
    wc_curve448_free(&priv);
    wc_curve448_free(&pub);
    return ret;
}

int curve448_base(uint8_t       out[CURVE448_POINT_SIZE],
                  const uint8_t scalar[CURVE448_SCALAR_SIZE])
{
    if (!out || !scalar) return -1;

    uint8_t sc[CURVE448_SCALAR_SIZE];
    memcpy(sc, scalar, CURVE448_SCALAR_SIZE);
    curve448_clamp(sc);

    int ret = wc_curve448_make_pub(CURVE448_POINT_SIZE, (byte *)out,
                                   CURVE448_SCALAR_SIZE, (const byte *)sc);
    return (ret == 0) ? 0 : -1;
}
