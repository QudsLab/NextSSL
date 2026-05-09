/* curve448.h — Curve448 raw DH surface (RFC 7748 §5, RFC 8031)
 *
 * "curve448" as a named surface refers to the *field and group primitive*:
 * the 56-byte u-coordinate scalar-multiplication function on Curve448-Goldilocks,
 * with no protocol framing.
 *
 * For key agreement use x448.h.
 * For EdDSA signatures use ed448.h.
 *
 * This surface exists so that higher-level protocols that need raw curve
 * operations (e.g. ECIES, HPKE) can depend on a named module rather than
 * digging into the backend directly.
 */
#ifndef NEXTSSL_CURVE448_SURFACE_H
#define NEXTSSL_CURVE448_SURFACE_H

#include <stdint.h>
#include <stddef.h>

#define CURVE448_POINT_SIZE  56u   /* u-coordinate, little-endian */
#define CURVE448_SCALAR_SIZE 56u

/* curve448 — RFC 7748 §5 scalar multiplication.
 * out = scalar * u  (Montgomery ladder)
 * Clamps the scalar per RFC 7748 before multiplying.
 * Returns 0 on success, -1 if result is the all-zero point. */
int curve448(uint8_t       out[CURVE448_POINT_SIZE],
             const uint8_t scalar[CURVE448_SCALAR_SIZE],
             const uint8_t u[CURVE448_POINT_SIZE]);

/* curve448_base — multiply the canonical base point (u=5) by scalar.
 * Returns 0 on success, -1 on error. */
int curve448_base(uint8_t       out[CURVE448_POINT_SIZE],
                  const uint8_t scalar[CURVE448_SCALAR_SIZE]);

/* curve448_clamp — apply RFC 7748 §5 Curve448 scalar clamping in-place. */
void curve448_clamp(uint8_t scalar[CURVE448_SCALAR_SIZE]);

#endif /* NEXTSSL_CURVE448_SURFACE_H */
