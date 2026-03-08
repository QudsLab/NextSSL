#ifndef NEXTSSL_SEED_KDF_H
#define NEXTSSL_SEED_KDF_H

#include <stddef.h>
#include <stdint.h>

/*
 * seed_kdf.h — HKDF-SHA256 based key derivation (RFC 5869)
 *
 * Primary use: stretching a shared secret or session key into subkeys.
 *
 *   salt   — optional (NULL → all-zero salt per RFC 5869 §2.2)
 *   info   — optional context/label (NULL ok)
 *   out_len — maximum 255 × 32 bytes (HKDF-SHA256 ceiling)
 *
 * Return: 0 on success, -1 on invalid arguments or length overflow.
 */
int seed_kdf_derive(const uint8_t *ikm,   size_t ikm_len,
                    const uint8_t *salt,  size_t salt_len,
                    const uint8_t *info,  size_t info_len,
                    uint8_t       *out,   size_t out_len);

#endif /* NEXTSSL_SEED_KDF_H */
