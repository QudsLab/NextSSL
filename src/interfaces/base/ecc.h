/**
 * @file ecc.h
 * @brief Layer 2: Elliptic Curve Cryptography aggregation
 * @layer base
 * @category ecc
 * @visibility semi-public
 * 
 * Low-level elliptic curve operations for custom protocols.
 * 
 * **Curves supported:**
 * - Curve25519 (X25519 key exchange)
 * - Curve448 (X448 key exchange)
 * - P-256 (NIST standard, ECDH + ECDSA)
 * - P-384 (NIST high-security)
 * - P-521 (NIST maximum security)
 * 
 * @note For standard ECDH, use dhcm.h. For ECDSA, use sign.h.
 * @warning Low-level API - most users should use higher-level interfaces
 */

#ifndef NEXTSSL_BASE_ECC_H
#define NEXTSSL_BASE_ECC_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Curve25519 ========== */

/**
 * Curve25519 scalar multiplication
 * 
 * @param result Output point (32 bytes)
 * @param scalar Scalar (32 bytes, clamped automatically)
 * @param point Input point (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Rejects low-order points
 */
NEXTSSL_BASE_API int nextssl_base_ecc_curve25519_scalarmult(
    uint8_t result[32],
    const uint8_t scalar[32],
    const uint8_t point[32]);

/**
 * Curve25519 base point scalar multiplication
 * 
 * @param result Output public key (32 bytes)
 * @param scalar Secret key (32 bytes, clamped automatically)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_curve25519_scalarmult_base(
    uint8_t result[32],
    const uint8_t scalar[32]);

/* ========== Curve448 ========== */

/**
 * Curve448 scalar multiplication
 * 
 * @param result Output point (56 bytes)
 * @param scalar Scalar (56 bytes)
 * @param point Input point (56 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_curve448_scalarmult(
    uint8_t result[56],
    const uint8_t scalar[56],
    const uint8_t point[56]);

/**
 * Curve448 base point scalar multiplication
 * 
 * @param result Output public key (56 bytes)
 * @param scalar Secret key (56 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_curve448_scalarmult_base(
    uint8_t result[56],
    const uint8_t scalar[56]);

/* ========== NIST P-256 ========== */

/**
 * P-256 point multiplication
 * 
 * @param result_x Output point X coordinate (32 bytes)
 * @param result_y Output point Y coordinate (32 bytes)
 * @param scalar Scalar (32 bytes)
 * @param point_x Input point X (32 bytes)
 * @param point_y Input point Y (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Validates input point is on curve
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p256_point_mul(
    uint8_t result_x[32], uint8_t result_y[32],
    const uint8_t scalar[32],
    const uint8_t point_x[32], const uint8_t point_y[32]);

/**
 * P-256 base point multiplication
 * 
 * @param result_x Output point X (32 bytes)
 * @param result_y Output point Y (32 bytes)
 * @param scalar Secret key (32 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p256_scalarmult_base(
    uint8_t result_x[32], uint8_t result_y[32],
    const uint8_t scalar[32]);

/**
 * P-256 point validation
 * 
 * @param point_x Point X coordinate (32 bytes)
 * @param point_y Point Y coordinate (32 bytes)
 * @return 1 if on curve, 0 if not, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p256_point_validate(
    const uint8_t point_x[32],
    const uint8_t point_y[32]);

/* ========== NIST P-384 ========== */

/**
 * P-384 base point multiplication
 * 
 * @param result_x Output point X (48 bytes)
 * @param result_y Output point Y (48 bytes)
 * @param scalar Secret key (48 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p384_scalarmult_base(
    uint8_t result_x[48], uint8_t result_y[48],
    const uint8_t scalar[48]);

/**
 * P-384 point validation
 * 
 * @param point_x Point X coordinate (48 bytes)
 * @param point_y Point Y coordinate (48 bytes)
 * @return 1 if on curve, 0 if not, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p384_point_validate(
    const uint8_t point_x[48],
    const uint8_t point_y[48]);

/* ========== NIST P-521 ========== */

/**
 * P-521 base point multiplication
 * 
 * @param result_x Output point X (66 bytes)
 * @param result_y Output point Y (66 bytes)
 * @param scalar Secret key (66 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p521_scalarmult_base(
    uint8_t result_x[66], uint8_t result_y[66],
    const uint8_t scalar[66]);

/**
 * P-521 point validation
 * 
 * @param point_x Point X coordinate (66 bytes)
 * @param point_y Point Y coordinate (66 bytes)
 * @return 1 if on curve, 0 if not, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_ecc_p521_point_validate(
    const uint8_t point_x[66],
    const uint8_t point_y[66]);

/**
 * Self-test for ECC operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_ecc_selftest(void);

#endif /* NEXTSSL_BASE_ECC_H */
