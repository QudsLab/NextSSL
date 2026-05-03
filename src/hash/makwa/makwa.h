/* makwa.h — Makwa password hashing (Plan 205)
 *
 * Source: Thomas Pornin (PHC submission, 2015).
 * Licence: MIT (see makwa-java/LICENSE in the original distribution).
 * Status: implemented locally — portable Montgomery modular-squaring backend.
 *
 * Makwa is based on modular squaring in a large integer ring (like RSA),
 * requiring a 2048-bit or 4096-bit modulus.
 *
 * PHS-like interface:
 *   int makwa_hash(const uint8_t *password, size_t passlen,
 *                  const uint8_t *salt, size_t saltlen,
 *                  const makwa_params_t *params,
 *                  uint8_t *out, size_t outlen);
 */
#ifndef MAKWA_H
#define MAKWA_H

#include <stddef.h>
#include <stdint.h>

/* Portable 2048-bit modular-squaring password hash */
int makwa_hash(const uint8_t *password, size_t passlen,
               const uint8_t *salt, size_t saltlen,
               uint32_t work_factor,
               uint8_t *out, size_t outlen);

#endif /* MAKWA_H */
